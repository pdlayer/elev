{
  description = "elev: a simple sudo alternative";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.stdenv.mkDerivation {
            pname = "elev";
            version = "1.0.0";

            src = ./.;

            nativeBuildInputs = [ pkgs.meson pkgs.ninja pkgs.pkg-config ];
            buildInputs = pkgs.lib.optionals (!pkgs.stdenv.isDarwin) [ pkgs.pam ];
          };
        });

      devShells = forAllSystems (system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = [ pkgs.meson pkgs.ninja pkgs.pkg-config pkgs.stdenv.cc ];
            buildInputs = pkgs.lib.optionals (!pkgs.stdenv.isDarwin) [ pkgs.pam ];
          };
        });

      nixosModules.default = { pkgs, ... }: {
        security.wrappers.elev = {
          source = "${self.packages.${pkgs.system}.default}/bin/elev";
          owner = "root";
          group = "root";
          setuid = true;
        };
      };
    };
}
