#!/bin/sh
# Copyright 2026 Petri Koistinen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

# Stamp the project version across the tree. The canonical version is
# CalVer YY.M.D.B, where B is a within-day 10-minute bucket
# (hour*10 + minute/10, 0..235). Updates:
#   VERSION                 canonical four-component string
#   .cargo/config.toml      REFINEID_VERSION (compiled into binaries)
#   Cargo.toml              workspace three-component SemVer projection
#
# Usage: script/version-stamp.sh

set -eu
cd "$(dirname "$0")/.."

year=$(date '+%y')
month=$(date '+%-m')
day=$(date '+%-d')
hour=$(date '+%-H')
minute=$(date '+%-M')
bucket=$((hour * 10 + minute / 10))
project_version="$year.$month.$day.$bucket"
semver="$year.$month.$day"

printf '%s\n' "$project_version" > VERSION

sed -i "s/^REFINEID_VERSION = { value = \"[0-9.]*\"/REFINEID_VERSION = { value = \"$project_version\"/" \
    .cargo/config.toml

sed -i "0,/^version = \"[0-9.]*\"$/s//version = \"$semver\"/" Cargo.toml

printf 'stamped %s (workspace %s)\n' "$project_version" "$semver" >&2
