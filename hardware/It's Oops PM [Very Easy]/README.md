![img](assets/images/banner.png)

<img src='assets/images/htb.png' style='margin-left: 20px; zoom: 80%;' align=left /> <font size='10'>It's Oops PM</font>

28<sup>th</sup> 2022 / Document No. D22.102.16

Prepared By: WizardAlfredo

Challenge Author(s): WizardAlfredo

Difficulty: <font color=green>Very Easy</font>

Classification: Official

# Synopsis

- Trigger a backdoor by analyzing the VHDL code of a TPM chip

## Description

- With the location of the underground bunker secured, the crew embarks on the next phase of their plan: assessing the feasibility of creating an underground tunnel to bypass the super mutant camp. They secure samples of water, soil, and air near the area. Scouring the wasteland for salvageable equipment, they stumble upon a dilapidated research facility where they find a cache of environmental sensors. Examining these sensors, the crew discovers they communicate with a satellite and contain a crypto-processor that encrypts their transmissions. After hand-drawing the diagrams and emulating the silicon chip's logic with VHDL, they uncover what appears to be a backdoor in the embedded logic that only triggers when a specific input is given to the system. Determined to exploit this, they turn to their tech specialist. "Can you connect to the satellite and activate it?

## Skills Required

- Basic source code analysis skills.
- Basic research skills.

## Skills Learned

- Improved understanding of FPGA programming in VHDL.
- Enhanced comprehension of hardware backdoors.

# Enumeration

## Analyzing the source code

By examining the `tpm.vhdl` code, we can ascertain that our goal is to trigger the backdoor to have the key printed in the chip's output. We are also provided with a `schematic.png` file that aids in understanding the chip's workflow.

![schematic](./challenge/schematic.png)

The basic workflow of the script is as follows:

1. Provide an **input**, and the chip will **encrypt** it and **output** the result.
2. If the input is a **specific** string, the multiplexer (MUX) will instead print the **key**.

The main function is essentially this:

```vhdl
begin
    ck : ckey port map(Key);
	enc: encryption port map (Data, Key, Encrypted);
	bd: backdoor port map (Data, B);

	process(Key, Encrypted, B)
	begin
		case B is
			when '1' =>
				for i in 0 to 15 loop
                    Output(i) <= Key(i);
				end loop;
			when others =>
				for i in 0 to 15 loop
                    Output(i) <= Encrypted(i);
				end loop;
		end case;
	end process;
end Behavioral;
```

In this code, the switch case is the multiplexer. The control signal `B` needs to be `"1"` for the key to be selected as the output. We also observe that `B` is the output of the backdoor mapping, initialized earlier in the `tpm.vhdl` code:

```vhdl
	component backdoor 
		port (
			D : in STD_LOGIC_VECTOR(15 downto 0);
			B : out STD_LOGIC
		);
	end component;
```

This implies that we need to further analyze the `backdoor.vhdl` code to determine how to set `B = '1'`. Opening the `backdoor.vhdl` file, we find the following code:

```vhdl
    constant pattern : STD_LOGIC_VECTOR(15 downto 0) := "1111111111101001";
begin
	process(D)
	begin
        if D = pattern then
            B <= '1';
        else
            B <= '0';
        end if;
	end process;
end Behavioral;
```

It is clear that the embedded logic/backdoor simply checks if the **input** to the chip **matches** this specific **constant** value and sets `B` accordingly.

# Solution

## Exploitation

### Connecting to the server

A pretty basic script for connecting to the server with `pwntools`:

```python
if __name__ == "__main__":
    r = remote("0.0.0.0", 1337)
    pwn()
```

### Triggering the Backdoor

From our analysis, we determined that we need to send the `"1111111111101001"` string as input to the chip.

```python
def trigger_backdoor():
    r.sendlineafter(b"Input : ", b"1111111111101001")
```

### Getting the flag

A final summary of the steps:

1. Connect to the chip.
2. Send the backdoor input.

This process is encapsulated in the pwn() function:

```python
def pwn():
    trigger_backdoor()
    r.recvuntil(b"flag: ")
    flag = toAscii(r.recvline())
    print(flag)
```
