# Postlinker

Link object files to an already compiled executable file.

Program takes two input files: one exectuable and one relocatable and one output file (new exec created from combining both input files).

Firstly it reads all header data from both files, then copies the
content of the **ET_EXEC** file to the **OUTPUT_FILE** with a **PAGE_SIZE** offset (`0x1000`)

Then sections with `ALLOC` flag are chosen from the **ET_REL** file in order to create
matching segments in the **OUTPUT_FILE**.
After the segments are created, first segment is moved to lover addresses
in order to make space for new segment headers.

Afterwards, when each segment and sections have assigned their addresses and offset, their headers
are written to the **OUTPUT_FILE**. In the end, relocations are handled, each relocation's address
and value of the according symbols is calculated accordingly and then saved to the **OUTPUT_FILE**.

All reading and writing to the files is done with `fread` and `fwrite`.

## Compilation
Simply run `make` in the main folder


## Usage
`./postlinker <ET_EXEC> <ET_REL> <OUTPUT_FILE>`
