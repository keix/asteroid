{
  description = "Asteroid Dev Environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }: flake-utils.lib.eachSystem [
    "x86_64-linux"
    "aarch64-linux"
    "aarch64-darwin"
  ] (system:
    let
      pkgs = import nixpkgs { inherit system; };
    in {
      devShells.default = pkgs.mkShell {
        name = "asteroid-shell";

        buildInputs = [
          pkgs.go
          pkgs.gotools
          pkgs.delve
          pkgs.redis
          pkgs.git
          pkgs.pkg-config
        ];

        shellHook = ''
          export CGO_ENABLED=1
          export GOMODCACHE=$HOME/.cache/go-build
          export GOPATH=$HOME/go

          echo "Asteroid DevShell loaded (${system})"
          echo "   go version: $(go version)"
          echo "   redis-server: $(redis-server --version | head -n 1)"
        '';
      };
    }
  );
}
