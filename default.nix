# Non-flake entry point: nix-build builds the ReFineID package with
# the nixpkgs on NIX_PATH.
{
  pkgs ? import <nixpkgs> { },
}:
pkgs.callPackage ./nix/package.nix { }
