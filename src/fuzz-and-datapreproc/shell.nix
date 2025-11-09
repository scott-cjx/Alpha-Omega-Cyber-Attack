{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  pname = "cyber-ai-demo-shell";
  buildInputs = with pkgs; [
    nmap
    nikto
    whatweb
    ffuf
    radare2
    aflplusplus
    jq
    python3
    curl
    wget
    git
  ];

  shellHook = ''
    echo "🔐 Cyber Research Environment Ready."
    echo "Tools available: nmap, nikto, whatweb, ffuf, radare2, aflplusplus, jq, python3, curl, wget, git"
    echo "Run scans and write outputs into ./outputs/"
  '';
}
