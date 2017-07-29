```
Input Message:
       00 11 22 33 
       44 55 66 77 
       88 99 aa bb 
       cc dd ee ff 
~~~~~~~~~~Cipher:
       00 01 02 03 
       04 05 06 07 
       08 09 0a 0b 
       0c 0d 0e 0f 
Initial round:
       00 40 80 c0 
       10 50 90 d0 
       20 60 a0 e0 
       30 70 b0 f0 
Round  1  sub_bytes:
       63 09 cd ba 
       ca 53 60 70 
       b7 d0 e0 e1 
       04 51 e7 8c 
  shift_rows:
       63 09 cd ba 
       53 60 70 ca 
       e0 e1 b7 d0 
       8c 04 51 e7 
  mix_columns:
       5f 57 f7 1d 
       72 f5 be b9 
       64 bc 3b f9 
       15 92 29 1a 
~~~~~~~~~~Cipher:
       10 11 12 13 
       14 15 16 17 
       18 19 1a 1b 
       1c 1d 1e 1f 
  add_round:
       4f 43 ef 01 
       63 e0 a7 a4 
       76 aa 21 e7 
       06 85 32 05 
Round  2  sub_bytes:
       84 1a df 7c 
       fb e1 5c 49 
       38 ac fd 94 
       6f 97 23 6b 
  shift_rows:
       84 1a df 7c 
       e1 5c 49 fb 
       fd 94 38 ac 
       6b 6f 97 23 
  mix_columns:
       bd 2b d1 61 
       2a 6a 92 5d 
       39 c4 44 a1 
       5d 38 3e 95 
~~~~~~~~~~Cipher:
       a5 73 c2 9f 
       a1 76 c4 98 
       a9 7f ce 93 
       a5 72 c0 9c 
  add_round:
       18 8a 78 c4 
       59 1c ed 2f 
       fb 00 8a 61 
       c2 a0 ad 09 
Round  3  sub_bytes:
       ad 7e bc 1c 
       cb 9c 55 15 
       0f 63 7e ef 
       25 e0 95 01 
  shift_rows:
       ad 7e bc 1c 
       9c 55 15 cb 
       7e ef 0f 63 
       01 25 e0 95 
  mix_columns:
       81 c9 b3 88 
       0d db 67 a1 
       ce 81 8c b5 
       0c 72 1e bd 
~~~~~~~~~~Cipher:
       16 51 a8 cd 
       02 44 be da 
       1a 5d a4 c1 
       06 40 ba de 
  add_round:
       97 cb a9 8e 
       5c 9f 3a e1 
       66 3f 28 0f 
       c1 a8 df 63 
Round  4  sub_bytes:
       88 1f d3 19 
       4a db 80 f8 
       33 75 34 76 
       78 c2 9e fb 
  shift_rows:
       88 1f d3 19 
       db 80 f8 4a 
       34 76 33 75 
       fb 78 c2 9e 
  mix_columns:
       b2 ab 5f 07 
       82 e6 af 8c 
       2d fb 10 00 
       81 27 3a 33 
~~~~~~~~~~Cipher:
       ae 87 df f0 
       0f f1 1b 68 
       a6 8e d5 fb 
       03 fc 15 67 
  add_round:
       1c a4 f9 04 
       05 17 21 70 
       f2 e0 c5 15 
       71 4f c1 54 
Round  5  sub_bytes:
       9c 49 99 f2 
       6b f0 fd 51 
       89 e1 a6 59 
       a3 84 78 20 
  shift_rows:
       9c 49 99 f2 
       f0 fd 51 6b 
       a6 59 89 e1 
       20 a3 84 78 
  mix_columns:
       ae 74 d7 db 
       b6 e0 3f 64 
       5b f8 56 c8 
       a9 22 7b 77 
~~~~~~~~~~Cipher:
       6d e1 f1 48 
       6f a5 4f 92 
       75 f8 eb 53 
       73 b8 51 8d 
  add_round:
       c3 1b a2 a8 
       57 45 c7 dc 
       aa b7 bd 99 
       e1 b0 28 fa 
Round  6  sub_bytes:
       2e af 3a c2 
       5b 6e c6 86 
       ac a9 7a ee 
       f8 e7 34 2d 
  shift_rows:
       2e af 3a c2 
       6e c6 86 5b 
       7a ee ac a9 
       2d f8 e7 34 
  mix_columns:
       b9 02 ae ef 
       51 e9 25 a0 
       c3 bd cd 8c 
       3c 29 b1 c7 
~~~~~~~~~~Cipher:
       c6 56 82 7f 
       c9 a7 99 17 
       6f 29 4c ec 
       6c d5 59 8b 
  add_round:
       7f cb c1 83 
       07 4e 0c 75 
       41 24 81 d5 
       43 3e 5d 4c 
Round  7  sub_bytes:
       d2 1f 78 ec 
       c5 2f fe 9d 
       83 36 0c 03 
       1a b2 4c 29 
  shift_rows:
       d2 1f 78 ec 
       2f fe 9d c5 
       0c 03 83 36 
       29 1a b2 4c 
  mix_columns:
       eb 3e 7d ed 
       b1 e7 75 6b 
       9e c9 35 91 
       1c e8 e9 44 
~~~~~~~~~~Cipher:
       3d e2 3a 75 
       52 47 75 e7 
       27 bf 9e b4 
       54 07 cf 39 
  add_round:
       d6 6c 5a b9 
       53 a0 ca 6c 
       a4 bc ab 5e 
       69 0f 5d 7d 
Round  8  sub_bytes:
       f6 50 be 56 
       ed e0 74 50 
       49 65 62 58 
       f9 76 4c ff 
  shift_rows:
       f6 50 be 56 
       e0 74 50 ed 
       62 58 49 65 
       ff f9 76 4c 
  mix_columns:
       51 9d a8 a9 
       74 a9 b3 74 
       c8 84 e6 a5 
       66 35 2c ea 
~~~~~~~~~~Cipher:
       0b dc 90 5f 
       c2 7b 09 48 
       ad 52 45 a4 
       c1 87 1c 2f 
  add_round:
       5a 5f 05 68 
       a8 d2 e1 f3 
       58 8d a3 b9 
       39 7d 88 c5 
Round  9  sub_bytes:
       be cf 6b 45 
       c2 b5 f8 0d 
       6a 5d 0a 56 
       12 ff c4 a6 
  shift_rows:
       be cf 6b 45 
       b5 f8 0d c2 
       0a 56 6a 5d 
       a6 12 ff c4 
  mix_columns:
       0f d2 54 4e 
       77 cc 30 f9 
       ee ad a8 6a 
       31 c0 3f c3 
~~~~~~~~~~Cipher:
       45 f5 a6 60 
       17 b2 d3 87 
       30 0d 4d 33 
       64 0a 82 0a 
  add_round:
       4a c5 64 2a 
       82 7e 3d f3 
       48 7e e5 e8 
       51 47 0c c9 
Round 10  sub_bytes:
       d6 a6 43 e5 
       13 f3 27 0d 
       52 f3 d9 9b 
       d1 a0 fe dd 
  shift_rows:
       d6 a6 43 e5 
       f3 27 0d 13 
       d9 9b 52 f3 
       dd d1 a0 fe 
  mix_columns:
       bd 74 63 e9 
       86 8f 0f 33 
       f0 c4 11 12 
       ea f4 c1 33 
~~~~~~~~~~Cipher:
       7c cf f7 1c 
       be b4 fe 54 
       13 e6 bb f0 
       d2 61 a7 df 
  add_round:
       c1 ca 70 3b 
       49 3b e9 52 
       07 3a aa b5 
       f6 a0 31 ec 
Round 11  sub_bytes:
       78 74 51 e2 
       3b e2 1e 00 
       c5 80 ac d5 
       42 e0 c7 ce 
  shift_rows:
       78 74 51 e2 
       e2 1e 00 3b 
       ac d5 c5 80 
       ce 42 e0 c7 
  mix_columns:
       af 5d 87 d5 
       86 6e e5 c8 
       90 1d fb 90 
       41 d3 ed 13 
~~~~~~~~~~Cipher:
       f0 1a fa fe 
       e7 a8 29 79 
       d7 a5 64 4a 
       b3 af e6 40 
  add_round:
       5f ba 50 66 
       9c c6 40 67 
       6a 34 9f 76 
       bf aa a7 53 
Round 12  sub_bytes:
       cf f4 53 33 
       de b4 09 85 
       02 18 db 38 
       08 ac 5c ed 
  shift_rows:
       cf f4 53 33 
       b4 09 85 de 
       db 38 02 18 
       ed 08 ac 5c 
  mix_columns:
       74 d8 9c 5b 
       27 a6 e8 e0 
       fa 95 3d 39 
       e4 26 31 2b 
~~~~~~~~~~Cipher:
       25 41 fe 71 
       9b f5 00 25 
       88 13 bb d5 
       5a 72 1c 0a 
  add_round:
       51 43 14 01 
       66 53 fb 92 
       04 95 86 25 
       95 03 e4 21 
Round 13  sub_bytes:
       d1 1a fa 7c 
       33 ed 0f 4f 
       f2 2a 44 3f 
       2a 7b 69 fd 
  shift_rows:
       d1 1a fa 7c 
       ed 0f 4f 33 
       44 3f f2 2a 
       fd 2a 7b 69 
  mix_columns:
       2c 30 b7 ee 
       21 6f 12 0d 
       a8 15 c7 a0 
       20 4a 5e 4f 
~~~~~~~~~~Cipher:
       4e 5a 66 99 
       a9 f2 4f e0 
       7e 57 2b aa 
       cd f8 cd ea 
  add_round:
       62 99 c9 23 
       7b 9d 45 f5 
       ce 5a ec 6d 
       b9 aa f4 a5 
Final round  sub_bytes:
       aa ee dd 26 
       21 5e 6e e6 
       8b be ce 3c 
       56 ac bf 06 
  shift_rows:
       aa ee dd 26 
       5e 6e e6 21 
       ce 3c 8b be 
       06 56 ac bf 
~~~~~~~~~~Cipher:
       24 fc 79 cc 
       bf 09 79 e9 
       37 1a c2 3c 
       6d 68 de 36 
  add_round:
       8e 51 ea 4b 
       a2 67 fc 49 
       b7 45 49 60 
       ca bf 90 89 
Output message:
       8e a2 b7 ca 
       51 67 45 bf 
       ea fc 49 90 
       4b 49 60 89
``` 
