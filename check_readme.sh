#!/usr/bin/env sh
## Checks that the README links all point to a point in the readme
for ID in $(grep -E "\\(#[a-z\\-]+\\)" README.md -o | grep -E "[a-z\\-]+" -o | sort | uniq)
do
if (grep "<a id=\"${ID}\">" README.md -o > /dev/null) then
  echo "✅  ${ID}"
else
  echo "❌  ${ID}"
fi
done
