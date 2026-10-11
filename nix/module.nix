# opaqued as a NixOS service under its own trust domain.
#
# Mirrors deploy/systemd/opaqued.service: a dedicated service account, a
# client group that alone may reach the socket surface, and the same systemd
# hardening. The daemon fails closed at startup unless every custody file is
# exclusively the service account's, so the config is installed (not linked
# from the Nix store) into /etc/opaque before each start.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.opaqued;
in
{
  options.services.opaqued = {
    enable = lib.mkEnableOption "the opaqued broker under its own trust domain";

    package = lib.mkOption {
      type = lib.types.package;
      description = "Package that provides bin/opaqued.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "opaque";
      description = "Service account that owns every custody file.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "opaque";
      description = "Primary group of the service account.";
    };

    clientGroup = lib.mkOption {
      type = lib.types.str;
      default = "opaque-clients";
      description = ''
        Accounts in this group may reach the socket and daemon token. Must
        match `[trust_domain] socket_group` in the config.
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Config installed as /etc/opaque/config.toml (0600, service account)
        before each start. It must set `[trust_domain] enforce = true`,
        `socket_group` and `socket_path = "/run/opaque/opaqued.sock"`. When
        null, provision /etc/opaque/config.toml yourself.
      '';
    };

    environment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = "Extra environment for the daemon.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = "/var/lib/opaque";
    };
    users.groups.${cfg.group} = { };
    users.groups.${cfg.clientGroup} = { };

    systemd.services.opaqued = {
      description = "Opaque broker daemon (trust-domain enforced)";
      documentation = [ "https://github.com/opaque-dev/opaque" ];
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      environment = {
        HOME = "/var/lib/opaque";
        OPAQUE_CONFIG = "/etc/opaque/config.toml";
      }
      // cfg.environment;

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        # Lets the daemon hand the socket surface to the client group (a
        # non-root owner may chgrp only to groups in its supplementary set).
        SupplementaryGroups = [ cfg.clientGroup ];
        ExecStartPre = lib.optional (cfg.configFile != null) (
          "+${pkgs.coreutils}/bin/install -m 0600 -o ${cfg.user} -g ${cfg.group} "
          + "${cfg.configFile} /etc/opaque/config.toml"
        );
        ExecStart = "${cfg.package}/bin/opaqued";
        Restart = "on-failure";
        RestartSec = 2;

        RuntimeDirectory = "opaque";
        RuntimeDirectoryMode = "0750";
        StateDirectory = "opaque";
        StateDirectoryMode = "0700";
        ConfigurationDirectory = "opaque";
        ConfigurationDirectoryMode = "0700";

        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ReadWritePaths = [ "/var/lib/opaque" ];
        PrivateTmp = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
        SystemCallArchitectures = "native";
      };
    };
  };
}
