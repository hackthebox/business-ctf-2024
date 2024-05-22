![img](assets/images/banner.png)

<img src='assets/images/htb.png' style='margin-left: 20px; zoom: 80%;' align=left /> <font size='10'>Six Five O Two</font>

28<sup>th</sup> 2022 / Document No. D22.102.16

Prepared By: WizardAlfredo

Challenge Author(s): WizardAlfredo

Difficulty: <font color=green>Medium</font>

Classification: Official

# Synopsis

- Develop your own 6502 assembly code and flash it to the emulated CPU to interact with the computer and display the flag on its console.

## Description

- In the tunnels beneath the wasteland, the crew makes their way to the heavily fortified Vault 79. After a perilous journey, they approach the access port on the side of the vault door frame, where the ancient 6502 CPU is located. They connect their Pip-Boy, which they have added a new mod that enables it to act as a flashing device, via the port's debugging interface. The Pip-Boy's screen illuminates the tunnel as green and red diodes flicker on the power box. The team's hardware specialist expertly manipulates the device, attempting to flash and override the firmware. With tense breaths held among the crew, a final green light overtakes the red. "Can you help manage to open the door?".

## Skills Required

- Basic research skills.
- Basic understanding of computer operations.

## Skills Learned

- Integrating online resources to write 6502 assembly code.
- Enhanced understanding of the 6502 CPU.
- Improved comprehension of CPU communication with ROMs and I/O.

# Enumeration

## Analyzing the source code

In this challenge, no source code files are provided for review, so we will connect to the instance.

### The HELP menu

We are greeted with the following HELP menu.

```

   **** 6502 FLASHING TOOL V2 ****
  16K RAM SYSTEM 32K ROM BYTES FREE

READY.
HELP
 PRINTL    .PRINTS THE LAYOUT OF THE COMPUTER
 FLASH B   .LOAD HEXADECIMAL BYTECODE INTO THE ROM
            THE CPU IS RESET AFTER EVERY FLASH
            EXAMPLE: FLASH FFFFFFFF....FFFFF
 RUN X     .EXECUTE X NUMBER OF OPCODES ON THE CPU
            EXAMPLE: RUN 10
 CONSOLE   .DISPLAYS THE OUTPUT CONSOLE
 HELP      .DISPLAYS THIS MENU

READY
```

This interface resembles that of a C64. It appears to be a tool for flashing a 6502 CPU. We have several options to choose from. Let us begin by viewing the layout of the computer we intend to program.

```
PRINTL

      +-----------+                              +------------+
      |           |  $0000-$3fff    $4000-$401f  |       HTB{ |
      |    RAM    |--------------..--------------|  ROM  .... |
      |           |              ||              |       ...} |
      +-----------+              ||              +------------+
                    +--------------------------+
                    |                          |
                    |       MOS 6502           |
                    |       1 MHz, 8-bit       |             HERE IS WHERE
                    |       Microprocessor     |             WE FLASH OUR
                    |                          |             BYTECODE.
                    +--------------------------+                   |
 +----------------+              ||              +-------------+   |
 |         .----. |              ||              |        .... |   |
 | CONSOLE |>   | |--------------''--------------|   ROM  .... |<--'
 |         '----' |  $6000-$601f    $8000-$FFFF  |        .... |
 +----------------+                              +-------------+

READY.
```

We observe two **ROM** chips: one that can be programmed and one that contains the flag. There is also some **RAM** and a **console**. Referring back to the help menu, we note that we can program the ROM using the `FLASH` command, execute a number of opcodes with the `RUN` command, and display the console output using the `CONSOLE` command. For a proof of concept, let’s try these commands.

`RUN 1`:

```
RUN 1
 PC   OC
 0000 00

READY.
```

The RUN command also shows the program counter's position and the opcode being executed.

`CONSOLE`:

```
CONSOLE
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

READY.
```

The console prints the 32 bytes located at \$6000 to \$601f.

### Address mappings

It is important to understand the address spaces reserved for each component:

\$0000 to \$3fff - **RAM**
\$4000 to \$401f - **ROM** containing the flag
\$6000 to \$601f - **Console**
\$8000 to \$ffff - Programmable **ROM**

These addresses are crucial for writing our assembly code.

### The reset vector

Now, we need to research the 6502 CPU. Fortunately, there are numerous emulators and guides available online. We will start with [this](http://www.6502.org/users/obelisk/6502/) page. Let us explore the [architecture](http://www.6502.org/users/obelisk/6502/architecture.html) of the 6502. Importantly:

> The only other reserved locations in the memory map are the very last 6 bytes of memory \$FFFA to \$FFFF which must be programmed with the addresses of the non-maskable interrupt handler (\$FFFA/B), the power on reset location (\$FFFC/D) and the BRK/interrupt request handler (\$FFFE/F) respectively.

As mentioned in the help menu, after a `FLASH` command, the CPU resets, jumping to the reset vector \$FFFC/D. Additional details about the reset process can be found on [this](https://www.pagetable.com/?p=410) page:

> On a RESET, the CPU loads the vector from \$FFFC/$FFFD into the program counter and continues fetching instructions from there.

### Recap

To summarize our findings:

- We can flash our own bytecode to the CPU using the `FLASH` command.
- We can run our code using the `RUN` command.
- Upon reset, the CPU jumps to the address at $FFFC/FFFD and fetches instructions from there.

# Solution

It is evident that since the only output method is the **console**, we will need to write assembly code to **copy** values from the **ROM** chip to the reserved console addresses.

## Exploitation

### Connecting to the server

A pretty basic script for connecting to the server with `pwntools`:

```python
if __name__ == "__main__":
    r = remote("0.0.0.0", 1337)
    pwn()
```

### Helper functions

We will create some helper functions to interact with the tool:

```python
def flash_rom(bytecode):
    r.sendlineafter(b"READY.", b"FLASH " + bytecode.encode())


def run_cpu(steps):
    r.sendlineafter(b"READY.", b"RUN " + str(steps).encode())


def print_console():
    r.sendlineafter(b"READY.", b"CONSOLE")
```

### Assembler

There are various ways to solve this challenge. Instead of manually writing the bytecode, we will use an assembler to write 6502 assembly code. An assembler can be found on [this](www.kingswood-consulting.co.uk/assemblers/) site. We can automate the assembly process with the following Python script:

```python
def assembler():
    with open("solver.a65", "w") as f:
        f.write(assembly)

    os.system("./as65  -l -m -w -h0 solver.a65 -osolver.rom")

    with open("solver.rom", "rb") as f:
        bytecode = f.read().hex()
    return bytecode
```

### The assembly

We need to write assembly code to **copy** the **ROM** containing the flag to the **console**. A simple loop will suffice. First, handle the reset vector:

```as
        code
        org $8000

        ldx #$00

        org $fffc
        dw $8000
        dw $ffff
```

We write the word \$8000 to addresses \$fffc/d and add padding at the end. In location \$8000, we write our program. Compiling this will generate bytecode of $8000 length, necessary for flashing the memory page completely. Next, write the loop:

```as
        code
        org $8000

        ldx #$00
LOOP    lda $4000,x
        sta $6000,x
        inx
        cmp #$20
        bne LOOP


        org $fffc
        dw $8000
        dw $ffff
```

This program **loads** values from address \$4000 plus the x register into the accumulator (`lda $4000,x`), **stores** the result at address \$6000 plus the x register (`sta $6000,x`), **increments** the x register (`inx`), and **compares** it to \$20 (`cmp #$20`). The loop continues until x equals \$20, effectively copying bytes from the ROM to the console.

### Flash and Run

Finally, flash the code to the ROM and run it using the helper functions:

### Getting the flag

The final summary of the steps:

1. Write the assembly code and assemble it.
2. Flash the code to the ROM.
3. Run the code.
4. Parse the flag from the console output.

This can be represented in code by the `pwn()` function:

```python
def pwn():
    r.recvuntil(b"READY.")
    bytecode = assembler()
    flash_rom(bytecode)
    run_cpu(160)
    print_console()
    flag = parse_flag()
    print(flag)
```
