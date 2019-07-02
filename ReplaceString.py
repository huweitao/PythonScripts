#-*- coding: UTF-8 -*-
import sys

def replaceString(oldOne,newOne,path):
	print("Replace %s to %s in %s" % (oldOne,newOne,path))
	content = ''
	with open(path, 'r') as f:
		content = f.read().replace(oldOne,newOne)
	# print content
	if len(content) > 0:
		with open(path, 'w') as f:
			f.write(content)

def main(oldOne,newOne,path):
	replaceString(oldOne,newOne,path)
	return True

if __name__ == '__main__':
	params = sys.argv
	if len(params) == 4:
		main(params[1],params[2],params[3])