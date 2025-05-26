<img src="../../assets/banner.png" style="zoom: 80%;" align=center />

<img src="../../assets/htb.png" style="zoom: 80%;" align='left' /><font size="5">Scrambled Payload</font>

  16<sup>th</sup> 5 2025

  Prepared By: Leeky

  Challenge Author: Leeky

  Difficulty: <font color=green>Easy</font>

  Classification: Official






# Synopsis

Scrambled Payload is an Easy Reversing challenge. Players will reverse engineer and deobfuscate a VBS file.

## Skills Required
    - Basic Visual Basic knowledge
## Skills Learned
    - Deobfuscating Visual Basic

# Solution

The challenge consists out of an obfuscated Visual Basic Script file. Running it will make nothing happen.
The most outer layer of obfuscation is just base64 encoding.
The next layer consists out of

`d="":for i=0 to length of array:d = d + Chr((Array(...)(i)+someOffset) mod 256):Next:Execute d`

instead of addition, multiplication or xor also happens.
This code is decoding strings at runtime and then executing them.
To get to the next layer we either replace Execute with some log or decode these arrays ourself.
Now we are in the last layer where we just need to decode the strings. The method used is the same as the first layer.

`Chr((211*95)mod 256)&Chr((187*169)mod 256)&Chr((152*21)mod 256)&Chr(109) ...`

by just evaluating these we get the original strings.

```
' Read computer name and base 64 encode it
Set b=CreateObject("ADODB.Stream"):b.Type=2:b.CharSet="us-ascii":b.Open:b.WriteText(CreateObject("WScript.Network").ComputerName):b.Position=0:b.Type=1:b.Position=0
Set n=CreateObject("Msxml2.DOMDocument.3.0").CreateElement("base64"):n.dataType="bin.base64":n.nodeTypedValue=b.Read
'n.text is base64 encoded computer name

Set r=New RegExp
' length = 36
r.Pattern="^....................................$":If Not r.Test(n.text)then WScript.Quit:End If
r.Pattern="^[MSy][FfK][ERT][yCM][efI][{31][KeN][jIS][Uol][z5j][}TR][DNV][4Qj][kY_][{Qw][Qz9][R{h][UF_][9Ns][l7W][SQI][lPb][9ZQ][QTJ][Y97][Ei3][IKL][x0U][iUX][FOE][QnU][xL8][RT_][lkL][d}q][9Sa]$":If Not r.Test(n.text)then WScript.Quit:End If
r.Pattern="^[{Sp][F7H][R1t][CHG][ze5][1na][D7N][jGJ][U}r][kBj][RSq][ZEN][3WQ][k9q][Kw9][XzV][WkR][FLi][m94][HW2][dQT][r{l][9}t][tpT][B8Y][A13][TI0][M7x][EZU][yFb][Quh][BRx][TsA][kQJ][3Xd][r39]$":If Not r.Test(n.text)then WScript.Quit:End If
r.Pattern="^[WoS][cFe][_yR][CzE][Xce][1HN][OYN][vTj][uDU][MYj][Rr7][GN4][tEQ][8kd][wnr][zpI][5Ra][F2x][9hP][xeW][9JQ][lRF][9ai][j7T][UVY][c3F][enI][fwx][vUH][xXF][Q1{][EVx][5TX][Fki][Zdw][of9]$":If Not r.Test(n.text)then WScript.Quit:End If

MsgBox("Correct!")
```

The code we are left with reads the computer name, base64 encodes it and matches it against a set of regex patterns. If all patterns match we get a "Correct!" otherwise the program exits.

The regex patterns expect a 36 character string and then check each character against a list for each character.
Since each character is checked 3 times, and all checks have to match for the input to be accepted, the correct character is the character in all check lists.

For `[MSy]` `[{Sp]` `[WoS]` this means the character has to be `S` as it is the only reappearing character.

Doing this for all 36 character gives us `SFRCe1NjUjRNQkwzRF9WQl9TY3IxUFQxTkd9`. We can base64 decode this to obtain the flag.

