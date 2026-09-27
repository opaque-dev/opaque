# typed: false
# frozen_string_literal: true

# Homebrew formula for Opaque — approval-gated secrets broker for AI coding tools
class Opaque < Formula
  desc "Approval-gated secrets broker for AI coding tools"
  homepage "https://github.com/opaque-dev/opaque"
  # Historical v0.4.0 artifacts retain BUSL-1.1. Update this license together
  # with the URLs/checksums when packaging an Apache-2.0 release.
  license "BUSL-1.1"

  on_macos do
    on_arm do
      url "https://github.com/opaque-dev/opaque/releases/download/v0.4.0/opaque-0.4.0-aarch64-apple-darwin.tar.gz"
      sha256 "238e9a02e9ffff7d4525d57cb879558fae407f220b8ddb491d99f3632cef4d1d"
    end

    on_intel do
      url "https://github.com/opaque-dev/opaque/releases/download/v0.4.0/opaque-0.4.0-x86_64-apple-darwin.tar.gz"
      sha256 "ab574420f0eda3955b18284fe2962074299c0bf258deb484ac4de6d7571278dd"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/opaque-dev/opaque/releases/download/v0.4.0/opaque-0.4.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "e09d4e91c48d35326695bc7dcb67def6810bd090d4af54dd90d4a083d272ce8b"
    end

    on_intel do
      url "https://github.com/opaque-dev/opaque/releases/download/v0.4.0/opaque-0.4.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "063bb0bd8850e24c1e5730b975c08d831d8e9ab7ff0ece5fdae1f75d2d25ad9b"
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
