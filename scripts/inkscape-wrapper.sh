#!/bin/sh
set -euo pipefail

input=""
output=""

for arg in "$@"; do
  case "$arg" in
    -V|--version)
      echo "Inkscape 1.4.3"
      exit 0
      ;;
    --export-filename=*)
      output="${arg#--export-filename=}"
      ;;
    --export-pdf=*)
      output="${arg#--export-pdf=}"
      ;;
    --export-ps=*)
      output="${arg#--export-ps=}"
      ;;
    --export-eps=*)
      output="${arg#--export-eps=}"
      ;;
    --export-png=*)
      output="${arg#--export-png=}"
      ;;
    --export-plain-svg=*)
      output="${arg#--export-plain-svg=}"
      ;;
    --export-type=*)
      # Ignore explicit type; we infer from output extension.
      ;;
    --export-latex)
      # Not supported; keep working for inkscapelatex=false.
      ;;
    -* )
      # Ignore other options like -D/-C/--export-dpi.
      ;;
    * )
      if [ -z "$input" ]; then
        input="$arg"
      fi
      ;;
  esac
done

if [ -z "$input" ] || [ -z "$output" ]; then
  echo "Usage: inkscape-wrapper <input.svg> --export-filename=<output>" >&2
  exit 1
fi

mkdir -p "$(dirname "$output")"

ext="${output##*.}"
case "$ext" in
  pdf|ps|eps|png)
    format="$ext"
    ;;
  *)
    format="pdf"
    ;;
esac

rsvg-convert -f "$format" -o "$output" "$input"
