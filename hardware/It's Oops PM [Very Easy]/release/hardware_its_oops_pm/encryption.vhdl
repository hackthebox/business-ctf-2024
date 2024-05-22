library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.NUMERIC_STD.ALL;

entity encryption is
	Port (
		D, K : in STD_LOGIC_VECTOR(15 downto 0);
		E : out STD_LOGIC_VECTOR(15 downto 0)
	);
end encryption;

architecture Behavioral of encryption is
begin
	process(D, K)
	begin
        for i in 1 to 15 loop
            E(i) <= D(i) XOR K(i);
        end loop;

        E(0) <= NOT K(0);
        E(6) <= NOT K(6);
        E(13) <= NOT K(13);
	end process;
end Behavioral;
