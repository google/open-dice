# Updating boringssl

The boringssl repo is configured as a git submodule in
`third_party/boringssl/src`. After updating the submodule, run:

```
cd third_party/boringssl
python src/util/generate_build_files.py gn
```
