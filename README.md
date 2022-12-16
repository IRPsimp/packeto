# packeto
A simple x86 PE packer implementation made in MASM.

Encrypts the text section using a xor key and stores it later in the PE File Header timestamp for decryption, also prints a MessageBox upon executable opening.

Takes the file name as a parameter.
