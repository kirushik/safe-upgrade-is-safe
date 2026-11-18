{
  description = "Dry-run Safe 1.1.1 -> 1.5.0 migrations on a local mainnet fork";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            foundry # anvil, forge, cast
            solc
            jq
            curl
          ];
          # Compile with the pinned Nix solc instead of letting forge download one.
          FOUNDRY_SOLC = "${pkgs.solc}/bin/solc";
          FOUNDRY_OFFLINE = "true";
        };
      });
    };
}
