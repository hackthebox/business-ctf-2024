library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.NUMERIC_STD.ALL;

entity backdoor is
	Port (
		D : in STD_LOGIC_VECTOR(15 downto 0);
		B : out STD_LOGIC
	);
end backdoor;

architecture Behavioral of backdoor is
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
