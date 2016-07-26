# MyNaim

MyNaim, an anagram of the malware family name 'Nymaim', is a collection of IDAPython deobfuscation scripts useful for anyone doing analysis of a Nymaim sample. This is especially so since their obfuscation techniques have more or less been the same throughout the years, so sharing my scripts might save the time of other analysts :)

# Feature List

1. Deobfuscates functions used to do a simple register push

  ![image](https://cloud.githubusercontent.com/assets/10496851/16363634/509514fc-3c03-11e6-9d2e-496a03e4e4dc.png)
  
  to
  
  ![image](https://cloud.githubusercontent.com/assets/10496851/16363583/6e697d3a-3c01-11e6-900a-8f163df74030.png)
2. Deobfuscates proxy function calls

  ![image](https://cloud.githubusercontent.com/assets/10496851/16363560/e14b95fa-3c00-11e6-9cea-92303cf1842e.png)
  
  to
  
  ![image](https://cloud.githubusercontent.com/assets/10496851/16363597/c85caea2-3c01-11e6-920d-f2091f1d15ad.png)
3. Provides a function to emulate the hashing and xor-ing of strings in Nymaim

  ![7996ad60-4839-11e6-9b94-111a776c0579](https://cloud.githubusercontent.com/assets/10496851/16775676/651e18a4-4894-11e6-994e-526e7ffd1583.png)
4. Provides a function to turn obfuscated offsets to their respective API addresses/namees

  ![screen shot 2016-07-26 at 5 51 32 pm](https://cloud.githubusercontent.com/assets/10496851/17133786/2bbcfa8c-535a-11e6-970d-5fe3bfdd7a07.png)

# Usage

1. Configure the path to PyEmu in `config.py`
2. Position the cursor anywhere within the text segment of the sample
3. Load `main.py` in IDAPro
4. In the IDAPython interpreter, execute `init()`, then `deobfuscate()` for as many times as you like :)

  ![image](https://cloud.githubusercontent.com/assets/10496851/16363652/10167bfe-3c04-11e6-80ee-5347e0152685.png)

Pro tip: You can actually re-run `deobfuscate()` after renaming your functions in order to update their names in the comments

# Dependencies

- [PyEmu](https://github.com/malikcjm/pyemu)
- [PyDasm](https://sourceforge.net/projects/winappdbg/files/additional%20packages/PyDasm/PyDasm-1.5-precompiled.zip/download)

# Todo

- Deobfuscate library calls
