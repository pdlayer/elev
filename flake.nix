{
  description = "elev: a simple sudo alternative";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
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

            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.pam ];

            installPhase = ''
              mkdir -p $out/bin $out/share/man/man1 $out/share/man/man5 $out/share/man/man7 $out/share/bash-completion/completions $out/share/zsh/site-functions
              make install DESTDIR=$out PREFIX=
            '';
          };
        });

      devShells = forAllSystems (system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = [ pkgs.pkg-config pkgs.gcc pkgs.gnumake ];
            buildInputs = [ pkgs.pam ];
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
