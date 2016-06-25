# Myamyn

Myamyn, the obfuscated form of the malware family name 'Nymaim', is a collection of IDAPython deobfuscation scripts useful for anyone doing analysis of a Nymaim sample.

# Usage

1. Configure the path to PyEmu in `config.py`
2. Load `deobfuscator.py` in IDAPro
3. Position the cursor anywhere within the text segment of the sample
4. In the IDAPython interpreter, execute `deobfuscate()`

# Dependencies

- [PyEmu](https://github.com/malikcjm/pyemu)
- [PyDasm](https://sourceforge.net/projects/winappdbg/files/additional%20packages/PyDasm/PyDasm-1.5-precompiled.zip/download)

# Todo

- Deobfuscate mov function calls
- Deobfuscate library calls
