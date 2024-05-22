library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.NUMERIC_STD.ALL;

entity tpm is
	Port (
		Data : in STD_LOGIC_VECTOR(15 downto 0);
		Output : out STD_LOGIC_VECTOR(15 downto 0)
	);
end tpm;

architecture Behavioral of tpm is
    signal Key : STD_LOGIC_VECTOR(15 downto 0);
	signal Encrypted : STD_LOGIC_VECTOR(15 downto 0);
	signal B: STD_LOGIC;

	component ckey
		port (
			K : out STD_LOGIC_VECTOR(15 downto 0)
		);
	end component;

	component encryption
		port (
			D, K : in STD_LOGIC_VECTOR(15 downto 0);
			E : out STD_LOGIC_VECTOR(15 downto 0)
		);
	end component;

	component backdoor 
		port (
			D : in STD_LOGIC_VECTOR(15 downto 0);
			B : out STD_LOGIC
		);
	end component;

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
