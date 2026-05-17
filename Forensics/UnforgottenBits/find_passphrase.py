#!/usr/bin/env python3

arr = open('wordlist.txt', 'r').readlines()

with open('output.txt', 'w') as file:
	for i in range(len(arr)):
		for j in range(len(arr)):
			file.write('yasuoaatrox' + arr[i].strip() + arr[j].strip() + '\n')