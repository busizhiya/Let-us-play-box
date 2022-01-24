num = 109
while num != 1 :
  if num>=32 and num<=126:
    print(chr(int(num)),end='')
  if num%2==0:
    num /= 2
  else :
    num *= 3
    num += 1
print('\n')
