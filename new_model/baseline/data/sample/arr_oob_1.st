PROGRAM arr_oob_1
VAR
  buf : ARRAY[0..9] OF INT;
  i : INT;
END_VAR
buf[i + 1] := 5;
END_PROGRAM
