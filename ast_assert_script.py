import ast
import sys
import copy
from time import sleep

def main():

	filename,function, class_name, api_name, output_filename = get_filename_function_class_api_outfile() 
	if(not filename):
		return

	with open(filename, "r") as source:
		tree = ast.parse(source.read())
	f = open(filename)
	lines = f.readlines()

	analysis = Analysis(function,filename,class_name,api_name,lines)
	analysis.visit(tree)
	while(len(analysis.target_functions) > 0):
		analysis.visit(tree)

		if(analysis.target_functions == analysis.old_target_functions and (analysis.target_classes == None or
			analysis.target_classes == analysis.old_classes)
			and (analysis.decode_identifiers == None or 
				(len(analysis.poss_identifier_funcs) == 0))):
			analysis.target_functions = []
		analysis.old_target_functions = copy.deepcopy(analysis.target_functions)
		analysis.old_classes = copy.deepcopy(analysis.target_classes)
		analysis.old_identifiers = copy.deepcopy(analysis.decode_identifiers)
		debugger(analysis)


	write_file(output_filename, analysis.line_list)
	f.close()


class Analysis(ast.NodeVisitor):
	def __init__(self, target_func,filename,class_name,api_name,file_lines):
		self.target_functions = [target_func]
		self.old_target_functions = [target_func]
		self.original_function = target_func
		self.cur_func = target_func
		self.target_classes = None
		self.old_classes = None
		if(class_name):
			self.target_classes = [class_name]
			self.old_classes = [class_name]
		self.api_list = None
		self.parameters = None
		self.old_identifiers = None
		self.decode_identifiers = None
		self.poss_identifier_funcs = None
		self.collect_assignments = None
		if(api_name):
			self.api_list = api_name.split('.')
			self.parameters = dict()
			self.decode_identifiers = list()
			self.old_identifiers = list()
			self.poss_identifier_funcs = list()
			self.collect_assignments = dict()
		self.filename = filename
		self.class_engage = False
		self.func_engage = False
		self.ident_search_mode = False
		self.lines = file_lines
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
	
		if((node.name in self.target_functions or (self.poss_identifier_funcs != None and node.name in 
			self.poss_identifier_funcs)) and ((self.class_engage and self.target_classes != None) 
			or self.target_classes == None)):
	
			self.cur_func = node.name
			if(self.poss_identifier_funcs != None and node.name in self.poss_identifier_funcs):
				if(node.name != self.original_function or len(self.poss_identifier_funcs) == 1):
					
					self.ident_search_mode = True
					self.poss_identifier_funcs.remove(node.name)
					
					self.func_engage = True
					self.generic_visit(node)
					self.func_engage = False
					self.ident_search_mode = False
			else:
				self.target_functions.remove(node.name)
				self.func_engage = True
				self.generic_visit(node)
				self.func_engage = False
				self.ident_search_mode = False

	def visit_Assert(self, node):
		if(not self.ident_search_mode):
			line_num = node.lineno - 1
			self.line_list.append(self.filename + ':' + str(line_num + 1) + ' ' + self.lines[line_num])
			self.generic_visit(node)

	def visit_Assign(self,node):
		if(self.ident_search_mode):
			print(ast.dump(node))
			print('----------------------=-------------------------')

			#print(self.cur_func)
			pass

	def visit_Call(self, node):
		
		if(self.api_list != None and (not self.ident_search_mode)):
			handle_api_search(self,node)


		if(not self.ident_search_mode):
			if(str(type(node.func)) == '<class \'_ast.Attribute\'>'):
				if(str(node.func.attr) in self.special_name_list):
					line_num = node.lineno - 1
					self.line_list.append(self.filename + ':' + str(line_num+1) + ' ' + self.lines[line_num])
				else:
					if(self.func_engage):
						self.target_functions.append(node.func.attr)

			if(str(type(node.func)) == '<class \'_ast.Name\'>'):
				if(str(node.func.id) in self.special_name_list):
					line_num = node.lineno - 1
					self.line_list.append(self.filename + ':' + str(line_num+1) + ' ' + self.lines[line_num])
				else:
					if(self.func_engage):
						self.target_functions.append(node.func.id)
			
	def visit_ClassDef(self,node):
		if(self.target_classes == None or node.name in self.target_classes):
			self.class_engage = True
			self.generic_visit(node)
			self.class_engage = False

			if(self.target_classes != None): 
				if(self.target_functions == self.old_target_functions):
					self.target_classes.remove(node.name)
					if(len(self.target_functions) > 0):
						if(len(node.bases) > 0):
							if(str(type(node.bases[0])) == '<class \'_ast.Attribute\'>'):
								self.target_classes.append(node.bases[0].value.id)
							else:
								self.target_classes.append(node.bases[0].id)
						else:
							self.target_classes = None



		

def get_filename_function_class_api_outfile():
	if(len(sys.argv) != 3 and len(sys.argv) != 5 and len(sys.argv) != 7 and len(sys.argv) != 9):
		print_usage()
		return None, None, None, None, None
	filename = str(sys.argv[1])
	function = str(sys.argv[2])
	class_name = None
	api_name = None
	output_filename = "results.out"

	flag_list = ['-c','-a','-o']

	if(len(sys.argv) > 3):
		cur_flag = ''
		for i in range(3, len(sys.argv)):
			if(i % 2 == 1):
				if(sys.argv[i] not in flag_list):
					print_usage()
					return None, None, None, None, None
				else:
					cur_flag = sys.argv[i]
			else:
				if(cur_flag == '-c'):
					class_name = sys.argv[i]
				if(cur_flag == '-a'):
					api_name = sys.argv[i]
				if(cur_flag == '-o'):
					output_filename = sys.argv[i]

	return filename,function,class_name, api_name,output_filename

def print_usage():
	print("USAGE: python filename function_name [-c class_name] [-a api_name] [-o output_filename]")

def write_file(results_file,line_list):
	with open(results_file, "w") as f:
		for line in line_list:
			f.write(line)

def debugger(analysis):
	print('===============DEBUGGING OUTPUT===============')
	print('Target Functions')
	print(analysis.target_functions)
	print('Target Functions (Previous Iteration)')
	print(analysis.old_target_functions)
	print('Current Function')
	print(analysis.cur_func)
	print('Target Classes')
	print(analysis.target_classes)
	print('Classes (Previous Iteration)')
	print(analysis.old_classes)
	print('API LIST')
	print(analysis.api_list)
	print('API parameters')
	print(analysis.parameters)
	print('API Unresolved Identifiers  (Previous Iteration)')
	print(analysis.old_identifiers)
	print('API Identifiers to Decode')
	print(analysis.decode_identifiers)
	print('Possible Functions to Look for Identifiers')
	print(analysis.poss_identifier_funcs)
	print('Class Engaged?')
	print(analysis.class_engage)
	print('Function Engaged?')
	print(analysis.func_engage)
	print('Identifier Search Mode Engaged?')
	print(analysis.ident_search_mode)
	print('Collected Line List')
	print(analysis.line_list)
	print('==============================================')

def handle_api_search(self,node):
	if(len(self.api_list) == 1 and str(type(node.func)) == '<class \'_ast.Name\'>'):
		if(str(node.func.id) == self.api_list[0]):
			if(len(node.args) > 0):
				for idx in range(len(node.args)):
					cur_arg = node.args[idx]

					if(str(type(cur_arg)) == '<class \'_ast.Constant\'>'):
						self.parameters[idx] = cur_arg.value

					if(str(type(cur_arg)) == '<class \'_ast.Name\'>'):
						self.decode_identifiers.append((cur_arg.id,idx, -1, None))
						if(self.original_function not in self.poss_identifier_funcs):
							self.poss_identifier_funcs.append(self.original_function)
						if(self.cur_func not in self.poss_identifier_funcs):
							self.poss_identifier_funcs.append(self.cur_func)


					if(str(type(cur_arg)) == '<class \'_ast.Dict\'>'):	
						for i in range(len(cur_arg.keys)):

							if(str(type(cur_arg.keys[i])) == '<class \'_ast.Constant\'>'):
								if(str(type(cur_arg.values[i])) == '<class \'_ast.Constant\'>'):
									self.parameters[cur_arg.keys[i].value] = cur_arg.values[i].value
								if(str(type(cur_arg.values[i])) == '<class \'_ast.Name\'>'):
									self.decode_identifiers.append((cur_arg.values[i].id,idx, -1,cur_arg.keys[i].value))
									if(self.original_function not in self.poss_identifier_funcs):
										self.poss_identifier_funcs.append(self.original_function)
									if(self.cur_func not in self.poss_identifier_funcs):
										self.poss_identifier_funcs.append(self.cur_func)

							if(str(type(cur_arg.keys[i])) == '<class \'_ast.Name\'>'):
								if(str(type(cur_arg.values[i])) == '<class \'_ast.Constant\'>'):
									self.parameters[cur_arg.keys[i].id] = cur_arg.values[i].value
								if(str(type(cur_arg.values[i])) == '<class \'_ast.Name\'>'):
									self.decode_identifiers.append((cur_arg.values[i].id, idx, -1,cur_arg.keys[i].id))
									if(self.original_function not in self.poss_identifier_funcs):
										self.poss_identifier_funcs.append(self.original_function)
									if(self.cur_func not in self.poss_identifier_funcs):
										self.poss_identifier_funcs.append(self.cur_func)

							if(str(type(cur_arg.values[i])) == '<class \'_ast.List\'>' or str(type(cur_arg.values[i])) 
									== '<class \'_ast.Tuple\'>'):
									self.parameters[cur_arg.keys[i].value] = []
									for j in range(len(cur_arg.values[i].elts)):
										if(str(type(cur_arg.values[i].elts[j])) == '<class \'_ast.Constant\'>'):
											self.parameters[cur_arg.keys[i].value].append(cur_arg.values[i].elts[j].value)
										if(str(type(cur_arg.values[i].elts[j])) == '<class \'_ast.Name\'>'):
											self.decode_identifiers.append((cur_arg.values[i].elts[j].id, idx, i, None))
											if(self.original_function not in self.poss_identifier_funcs):
												self.poss_identifier_funcs.append(self.original_function)
											if(self.cur_func not in self.poss_identifier_funcs):
												self.poss_identifier_funcs.append(self.cur_func)


					if(str(type(cur_arg)) == '<class \'_ast.List\'>'):
						self.parameters[idx] = []
						for i in range(len(cur_arg.elts)):
							if(str(type(cur_arg.elts[i])) == '<class \'_ast.Constant\'>'):
								self.parameters[idx].append(cur_arg.elts[i].value)
							if(str(type(cur_arg.elts[i])) == '<class \'_ast.Name\'>'):
								self.decode_identifiers.append((cur_arg.elts[i].id, idx, i, None))
								if(self.original_function not in self.poss_identifier_funcs):
									self.poss_identifier_funcs.append(self.original_function)
								if(self.cur_func not in self.poss_identifier_funcs):
									self.poss_identifier_funcs.append(self.cur_func)
								

			for idx in range(len(node.keywords)):
					cur_keyword = node.keywords[idx]
					if(str(type(cur_keyword.value)) == '<class \'_ast.Constant\'>'):
						self.parameters[cur_keyword.arg] = cur_keyword.value.value
					if(str(type(cur_keyword.value)) == '<class \'_ast.Name\'>'):
						self.decode_identifiers.append((cur_keyword.value.id, idx+total_idx, -1, cur_keyword.arg))
						if(self.original_function not in self.poss_identifier_funcs):
							self.poss_identifier_funcs.append(self.original_function)
						if(self.cur_func not in self.poss_identifier_funcs):
							self.poss_identifier_funcs.append(self.cur_func)
								
			#print(self.parameters)
			#print(self.decode_identifiers)


	if(str(type(node.func)) == '<class \'_ast.Attribute\'>'):
		print(node.func.attr)
		top_lvl_attr = node.func
		left_satisfied = len(self.api_list)
		set_type = top_lvl_attr
		while(True):
			if(str(type(set_type)) == '<class \'_ast.Name\'>'):
				print(set_type.id)
				if(set_type.id in self.api_list):
					left_satisfied = left_satisfied - 1
					break
				break
			if(str(type(set_type)) == '<class \'_ast.Attribute\'>'):
				print(set_type.attr)
				if(set_type.attr in self.api_list):
					left_satisfied = left_satisfied - 1
				set_type = set_type.value
				continue
			if(str(type(set_type)) == '<class \'_ast.Call\'>'):
				set_type = set_type.func
				continue
			break
		print('bruh time')
		print(left_satisfied)
		if(left_satisfied == 0):
			total_idx = 0
			print('starting parsing of first API Call')
			if(len(node.args) > 0):
				for idx in range(len(node.args)):
					cur_arg = node.args[idx]
					total_idx = total_idx + 1
					if(str(type(cur_arg)) == '<class \'_ast.Constant\'>'):
						self.parameters[idx] = cur_arg.value

					if(str(type(cur_arg)) == '<class \'_ast.Name\'>'):
						self.decode_identifiers.append((cur_arg.id,idx, -1, None))
						if(self.original_function not in self.poss_identifier_funcs):
							self.poss_identifier_funcs.append(self.original_function)
						if(self.cur_func not in self.poss_identifier_funcs):
							self.poss_identifier_funcs.append(self.cur_func)

					if(str(type(cur_arg)) == '<class \'_ast.Dict\'>'):	
						for i in range(len(cur_arg.keys)):
	
							if(str(type(cur_arg.keys[i])) == '<class \'_ast.Constant\'>'):

								if(str(type(cur_arg.values[i])) == '<class \'_ast.Constant\'>'):
									self.parameters[cur_arg.keys[i].value] = cur_arg.values[i].value

								if(str(type(cur_arg.values[i])) == '<class \'_ast.Name\'>'):
									self.decode_identifiers.append((cur_arg.values[i].id,idx,-1,cur_arg.keys[i].value))
									if(self.original_function not in self.poss_identifier_funcs):
										self.poss_identifier_funcs.append(self.original_function)
									if(self.cur_func not in self.poss_identifier_funcs):
										self.poss_identifier_funcs.append(self.cur_func)

								if(str(type(cur_arg.values[i])) == '<class \'_ast.List\'>' or str(type(cur_arg.values[i])) 
									== '<class \'_ast.Tuple\'>'):
									self.parameters[cur_arg.keys[i].value] = []
									for j in range(len(cur_arg.values[i].elts)):
										if(str(type(cur_arg.values[i].elts[j])) == '<class \'_ast.Constant\'>'):
											self.parameters[cur_arg.keys[i].value].append(cur_arg.values[i].elts[j].value)
										if(str(type(cur_arg.values[i].elts[j])) == '<class \'_ast.Name\'>'):
											self.decode_identifiers.append((cur_arg.values[i].elts[j].id, idx, i, None))
											if(self.original_function not in self.poss_identifier_funcs):
												self.poss_identifier_funcs.append(self.original_function)
											if(self.cur_func not in self.poss_identifier_funcs):
												self.poss_identifier_funcs.append(self.cur_func)

							if(str(type(cur_arg.keys[i])) == '<class \'_ast.Name\'>'):
								if(str(type(cur_arg.values[i])) == '<class \'_ast.Constant\'>'):
									self.parameters[cur_arg.keys[i].id] = cur_arg.values[i].value
								if(str(type(cur_arg.values[i])) == '<class \'_ast.Name\'>'):
									self.decode_identifiers.append((cur_arg.values[i].id,idx, -1,cur_arg.keys[i].id))
									if(self.original_function not in self.poss_identifier_funcs):
										self.poss_identifier_funcs.append(self.original_function)
									if(self.cur_func not in self.poss_identifier_funcs):
										self.poss_identifier_funcs.append(self.cur_func)


					if(str(type(cur_arg)) == '<class \'_ast.List\'>' or str(type(cur_arg)) == '<class \'_ast.Tuple\'>'):
						self.parameters[idx] = []
						for i in range(len(cur_arg.elts)):
							if(str(type(cur_arg.elts[i])) == '<class \'_ast.Constant\'>'):
								self.parameters[idx].append(cur_arg.elts[i].value)
							if(str(type(cur_arg.elts[i])) == '<class \'_ast.Name\'>'):
								self.decode_identifiers.append((cur_arg.elts[i].id, idx, i, None))
								if(self.original_function not in self.poss_identifier_funcs):
									self.poss_identifier_funcs.append(self.original_function)
								if(self.cur_func not in self.poss_identifier_funcs):
									self.poss_identifier_funcs.append(self.cur_func)

			for idx in range(len(node.keywords)):
					cur_keyword = node.keywords[idx]
					if(str(type(cur_keyword.value)) == '<class \'_ast.Constant\'>'):
						self.parameters[cur_keyword.arg] = cur_keyword.value.value
					if(str(type(cur_keyword.value)) == '<class \'_ast.Name\'>'):
						self.decode_identifiers.append((cur_keyword.value.id,idx+total_idx, -1, cur_keyword.arg))
						if(self.original_function not in self.poss_identifier_funcs):
							self.poss_identifier_funcs.append(self.original_function)
						if(self.cur_func not in self.poss_identifier_funcs):
							self.poss_identifier_funcs.append(self.cur_func)
			#print(self.parameters)
			#print(self.decode_identifiers)
if __name__ == "__main__":
	main()