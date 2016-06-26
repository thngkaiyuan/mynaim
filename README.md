# Myamyn

Myamyn, the obfuscated form of the malware family name 'Nymaim', is a collection of IDAPython deobfuscation scripts useful for anyone doing analysis of a Nymaim sample. This is especially so since their obfuscation techniques have more or less been the same throughout the years, so sharing my scripts might save the time of other analysts :)

# Feature List

1. Deobfuscates functions used to do a simple register push
2. Deobfuscates proxy function calls
3. Provides a function to emulate the hashing and xor-ing of strings in Nymaim

# Usage

1. Configure the path to PyEmu in `config.py`
2. Position the cursor anywhere within the text segment of the sample
3. Load `main.py` in IDAPro
4. In the IDAPython interpreter, execute `init()`, then `deobfuscate()` for as many times as you like :)

Pro tip: You can actually re-run `deobfuscate()` after renaming your functions in order to update their names in the comments

# Dependencies

- [PyEmu](https://github.com/malikcjm/pyemu)
- [PyDasm](https://sourceforge.net/projects/winappdbg/files/additional%20packages/PyDasm/PyDasm-1.5-precompiled.zip/download)

# Todo

- Deobfuscate library calls
