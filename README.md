# promon-unpacker
A tool for unpacking libraries protected by Promon SHIELD.
Works on v8/v9 versions.

# Warning
im shit in rust, youre free to insult me as much as you want if you see shitcode
i coded this in rust cuz i was bored and wanted to code in rust

you need to first decrypt .gcc to get the descriptor offset, let descriptor offset invalid but update ncc address then decrypt the lib, open the decrypted lib in a dissassembler then find the descriptor array and once you found it, replace the invalid offset with correct descriptor offset, then rerun the decryptor and text will be decrypted too
yes annoying as hell..

# How to use
1. update offsets in promon.rs, read warning before
2. run decryptor