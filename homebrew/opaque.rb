# typed: false
# frozen_string_literal: true

# Homebrew formula for Opaque — approval-gated secrets broker for AI coding tools
class Opaque < Formula
  desc "Approval-gated secrets broker for AI coding tools"
  homepage "https://github.com/opaque-dev/opaque"
  # Releases from v0.6.0 ship under Apache-2.0; earlier published artifacts
  # retain the BUSL-1.1 terms they were released with.
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/opaque-dev/opaque/releases/download/v0.6.0/opaque-0.6.0-aarch64-apple-darwin.tar.gz"
      sha256 "b914f36df06520995506d35da3e1125e1099eaf01c66121209c26465137f52eb"
    end

    on_intel do
      url "https://github.com/opaque-dev/opaque/releases/download/v0.6.0/opaque-0.6.0-x86_64-apple-darwin.tar.gz"
      sha256 "b3b07f6e8ebe074f456c349262d5ad99d4e2a7067aa0de81409bfb0d847c4d04"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/opaque-dev/opaque/releases/download/v0.6.0/opaque-0.6.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "1cc53846fb10958b7639b57607ee0eff2f3490c472ca4bbb7f68c217343e71e8"
    end

    on_intel do
      url "https://github.com/opaque-dev/opaque/releases/download/v0.6.0/opaque-0.6.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "447041e7513e26ce7fd4c5e28fec3509f23a7a8310a477a39e44b6fec53f261f"
    end
  end

  def install
    bin.install "opaqued"
    bin.install "opaque"
    bin.install "opaque-mcp"
    bin.install "opaque-approve-helper"
    bin.install "opaque-web"
    # Older tagged archives predate these tools. A release containing them must
    # make them available without breaking installation of the existing tags.
    bin.install "opaque-mcp-contract" if File.file?("opaque-mcp-contract")
    bin.install "opaque-approver" if File.file?("opaque-approver")
    bin.install "opaque-evidence" if File.file?("opaque-evidence")
    prefix.install "Opaque Reviewer.app" if OS.mac? && File.directory?("Opaque Reviewer.app")
  end

  def caveats
    return unless OS.mac? && (prefix/"Opaque Reviewer.app").directory?

    <<~EOS
      The trusted reviewer is available at:
        #{prefix}/Opaque Reviewer.app
      Follow its enrollment guide before reviewing work:
        https://github.com/opaque-dev/opaque/blob/main/crates/opaque-approver/README.md
      Installing the formula does not enroll a broker or register a notice handler.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/opaque --version")
  end
end
