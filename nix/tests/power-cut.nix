# Two-machine test: the broker loses power while an MCP effect is in flight.
#
# `workstation` runs opaqued under the enforced trust-domain split, with an
# `agent` account in the client group and an `outsider` account outside it.
# `provider` runs a synthetic MCP upstream that durably records each effect
# before answering, so the effect count survives the broker's power cut.
#
# What this verifies about opaque: the client-group socket surface, custody
# file permissions, and that an invocation charged before dispatch is
# recovered as `unknown` after real power loss (guest page cache discarded,
# unlike kill -9) and is never replayed.
#
# What is test infrastructure, not opaque behaviour: the MCP gateway's
# insecure fixture mode only dials 127.0.0.1, so a loopback forwarder carries
# the broker's traffic to `provider`, and iptables owner rules restrict the
# forwarder to the broker's uid. Those rules are a deployment pattern under
# test; opaque does not install or enforce them.
{ module, opaque }:
{ pkgs, ... }:
let
  harness = ./power-cut;
  python = "${pkgs.python3}/bin/python3 -B";
  client = "${python} ${harness}/opaque_call.py --socket /run/opaque/opaqued.sock --token-file /run/opaque/daemon.token";
  mockToken = "synthetic-mcp-token";
in
{
  name = "opaque-power-cut";

  nodes.provider = {
    networking.firewall.allowedTCPPorts = [ 8080 ];
    users.users.mock = {
      isSystemUser = true;
      group = "mock";
    };
    users.groups.mock = { };
    systemd.services.mock-mcp = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        User = "mock";
        StateDirectory = "mock-mcp";
        ExecStart =
          "${python} ${harness}/mock_mcp.py --port 8080 --state-dir /var/lib/mock-mcp "
          + "--token-file ${pkgs.writeText "mock-token" mockToken}";
      };
    };
  };

  nodes.workstation = {
    imports = [ module ];

    # No background writeback: after crash() only data that something fsynced
    # survives, independent of how long the VM ran before the power cut.
    boot.kernel.sysctl = {
      "vm.dirty_writeback_centisecs" = 0;
      "vm.dirty_expire_centisecs" = 360000;
    };

    services.opaqued = {
      enable = true;
      package = opaque;
      environment = {
        OPAQUE_INSECURE_AUTO_APPROVE = "1";
        RUST_LOG = "info";
      };
    };

    users.users.agent = {
      isNormalUser = true;
      extraGroups = [ "opaque-clients" ];
    };
    users.users.outsider.isNormalUser = true;
    users.users.egress = {
      isSystemUser = true;
      group = "egress";
    };
    users.groups.egress = { };

    environment.systemPackages = [
      opaque
      pkgs.curl
    ];

    # The config embeds a trust anchor generated on first boot, so it is
    # provisioned here instead of through services.opaqued.configFile.
    systemd.services.opaque-fixture = {
      description = "Provision the synthetic MCP registry and broker config (test only)";
      wantedBy = [ "multi-user.target" ];
      requiredBy = [ "opaqued.service" ];
      before = [ "opaqued.service" ];
      unitConfig.ConditionPathExists = "!/etc/opaque/config.toml";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      path = [
        opaque
        pkgs.gawk
        pkgs.gnused
      ];
      script = ''
        install -d -m 0700 /root/org
        opaque bundle keygen --out /root/org/signing.key > /root/org/keygen.out
        anchor=$(awk '/trust anchor:/ { print $3 }' /root/org/keygen.out)
        test ''${#anchor} -eq 64

        install -d -m 0700 -o opaque -g opaque /var/lib/opaque /var/lib/opaque/state /etc/opaque
        opaque bundle sign --manifest ${harness}/registry.toml --key /root/org/signing.key \
          --out /var/lib/opaque/state/registry.bundle --expires-days 30
        printf %s ${mockToken} > /var/lib/opaque/state/notes-token
        sed "s/@TRUST_ANCHOR@/$anchor/" ${harness}/opaqued.toml > /etc/opaque/config.toml
        for file in /var/lib/opaque/state/registry.bundle /var/lib/opaque/state/notes-token /etc/opaque/config.toml; do
          chown opaque:opaque "$file"
          chmod 0600 "$file"
        done
        # The power cut can land seconds after first boot. Without this, the
        # config survives as an empty file, which opaqued loads as defaults.
        sync
      '';
    };

    systemd.services.egress-forwarder = {
      description = "Loopback forwarder to the provider (test infrastructure)";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        User = "egress";
        ExecStart = "${pkgs.socat}/bin/socat TCP-LISTEN:18080,bind=127.0.0.1,fork,reuseaddr TCP:provider:8080";
        Restart = "always";
      };
    };

    # Deployment pattern under test: only the broker's uid may use the
    # forwarder, and only the forwarder may reach the provider.
    networking.firewall.extraCommands = ''
      iptables -N opaque-egress 2>/dev/null || iptables -F opaque-egress
      iptables -C OUTPUT -j opaque-egress 2>/dev/null || iptables -A OUTPUT -j opaque-egress
      iptables -A opaque-egress -o lo -p tcp --dport 18080 -m owner ! --uid-owner opaque -j REJECT
      iptables -A opaque-egress -p tcp -d provider --dport 8080 -m owner ! --uid-owner egress -j REJECT
    '';
  };

  testScript = ''
    import json
    import uuid

    def call(method, params, user="agent"):
        out = workstation.succeed(
            f"runuser -u {user} -- ${client} {method} '{json.dumps(params)}'"
        )
        return json.loads(out)

    def note(invocation_id, message):
        return {
            "invocation_id": invocation_id,
            "route": "post_note",
            "arguments": {"message": message},
            "expires_in_secs": 300,
        }

    def effects():
        return int(provider.succeed("wc -l < /var/lib/mock-mcp/effects").strip())

    def broker_up():
        # Software emulation needs ~2 minutes to boot; KVM needs ~20 seconds.
        workstation.wait_for_unit("opaqued.service", timeout=300)
        workstation.wait_until_succeeds("test -S /run/opaque/opaqued.sock", timeout=300)
        workstation.wait_until_succeeds("test -s /run/opaque/daemon.token", timeout=60)

    start_all()
    provider.wait_for_unit("mock-mcp.service")
    provider.wait_for_open_port(8080)
    broker_up()

    with subtest("only the client group reaches the broker's socket surface"):
        workstation.succeed("stat -c '%U %G %a' /run/opaque | grep -qx 'opaque opaque-clients 750'")
        workstation.succeed("stat -c '%U %G %a' /run/opaque/opaqued.sock | grep -qx 'opaque opaque-clients 660'")
        workstation.succeed("stat -c '%U %G %a' /run/opaque/daemon.token | grep -qx 'opaque opaque-clients 640'")
        workstation.fail("runuser -u outsider -- cat /run/opaque/daemon.token")
        workstation.succeed("runuser -u agent -- cat /run/opaque/daemon.token")
        workstation.fail("runuser -u agent -- ls /var/lib/opaque")
        for path in ["/etc/opaque/config.toml", "/var/lib/opaque/state/notes-token"]:
            workstation.fail(f"runuser -u agent -- cat {path}")

    with subtest("egress to the provider is the broker's alone (deployment pattern)"):
        # Any HTTP answer makes curl exit 0, so these fail only on a refused connection.
        workstation.fail("runuser -u agent -- curl -sS -m 5 -o /dev/null http://provider:8080/mcp")
        workstation.fail("runuser -u agent -- curl -sS -m 5 -o /dev/null http://127.0.0.1:18080/mcp")

    with subtest("positive control: an unheld call completes"):
        completed = note(str(uuid.uuid4()), "positive control")
        reply = call("mcp_call", completed)
        receipt = reply["result"]["receipt"]
        assert receipt["state"] == "accepted", reply
        assert effects() == 1

    with subtest("power cut mid-effect: charged, unknown, never replayed"):
        held = note(str(uuid.uuid4()), "held call")
        provider.succeed("touch /var/lib/mock-mcp/hold")
        workstation.succeed(
            f"systemd-run --uid=agent --unit=held-call -- ${client} --hold-open mcp_call '{json.dumps(held)}'"
        )
        provider.wait_until_succeeds("test $(wc -l < /var/lib/mock-mcp/effects) -eq 2", timeout=120)

        workstation.crash()
        workstation.start()
        broker_up()

        receipt = call("mcp_get", {"invocation_id": held["invocation_id"]})["result"]["receipt"]
        assert receipt["state"] == "unknown", receipt
        assert receipt["code"] == "interrupted", receipt
        assert receipt["attempt_charged"] is True, receipt

        retry = call("mcp_call", held)
        assert retry.get("error", {}).get("code") == "mcp_unavailable", retry

        # The receipt committed before the power cut is still intact.
        receipt = call("mcp_get", {"invocation_id": completed["invocation_id"]})["result"]["receipt"]
        assert receipt["state"] == "accepted", receipt

        provider.succeed("rm /var/lib/mock-mcp/hold")
        assert effects() == 2
  '';
}
