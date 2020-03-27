import ast
import sys


def main():

	filename,function = get_filename_and_function()
	if(not filename):
		return

	with open(filename, "r") as source:
		tree = ast.parse(source.read())
	f = open(filename)
	lines = f.readlines()

	analysis = Analysis(function,filename,lines)
	analysis.visit(tree)
	while(len(analysis.function_list) > 0):
		old_list = analysis.function_list
		analysis.target = ''
		analysis.visit(tree)
		if(analysis.function_list == old_list):
			analysis.function_list = []

	write_file("results.out", analysis.line_list)
	f.close()

#TO-DO recursive cycle detection

class Analysis(ast.NodeVisitor):
	def __init__(self, target_func,filename,file_lines):
		self.target = target_func
		self.filename = filename
		self.engage = False
		self.lines = file_lines
		self.function_list = []
		self.line_list = []
		self.special_name_list = ['assertEqual',
									'assertNotEqual',
									'assertTrue',
									'assertFalse',
									'assertIs',
									'assertIsNot',
									'assertIsNone',
									'assertIsNotNone',
									'assertIn',
									'assertNotIn',
									'assertIsInstance',
									'assertRaises',
									'assertRaisesRegex',
									'assertWarns',
									'assertWarnsRegex',
									'assertLogs',
									'assertAlmostEqual',
									'assertNotAlmostEqual',
									'assertGreater',
									'assertGreaterEqual',
									'assertLess',
									'assertLessEqual',
									'assertRegex',
									'assertNotRegex',
									'assertCountEqual',
									'assertMultiLineEqual',
									'assertSequenceEqual',
									'assertListEqual',
									'assertTupleEqual',
									'assertSetEqual',
									'assertDictEqual',
									'assert_equal',
									'assert_true',
									'assert_false',
									'assert_not_equals']

	def visit_FunctionDef(self, node):
		if(node.name == self.target):
			self.engage = True
			self.generic_visit(node)
		if(node.name in self.function_list):
			self.function_list.remove(node.name)
			self.generic_visit(node)
				

	def visit_Assert(self, node):
		line_num = node.lineno - 1
		self.line_list.append(self.filename + ':' + str(line_num + 1) + ' ' + self.lines[line_num])
		self.generic_visit(node)

	def visit_Call(self, node):

		if(str(type(node.func)) == '<class \'_ast.Attribute\'>'):
			if(str(node.func.attr) in self.special_name_list):
				line_num = node.lineno - 1
				self.line_list.append(self.filename + ':' + str(line_num+1) + ' ' + self.lines[line_num])
			
		if(str(type(node.func)) == '<class \'_ast.Name\'>'):
			if(str(node.func.id) in self.special_name_list):
				line_num = node.lineno - 1
				self.line_list.append(self.filename + ':' + str(line_num+1) + ' ' + self.lines[line_num])
			else:
				self.function_list.append(node.func.id)
			

def get_filename_and_function():
	if(len(sys.argv) != 3):
		print("Please provide a script to execute (only one script), and one function name only")
		return None, None
	filename = str(sys.argv[1])
	function = str(sys.argv[2])
	return filename,function

def write_file(results_file,line_list):
	with open(results_file, "w") as f:
		for line in line_list:
			f.write(line)

if __name__ == "__main__":
	main()