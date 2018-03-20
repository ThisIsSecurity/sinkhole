from binaryninja import *

import re

JUMPS = ['jo', 'jno', 'js', 'jns', 'je', 'jz', 'jne', 'jnz',
         'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe', 'jna',
         'ja', 'jnbe', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng',
         'jg', 'jnle', 'jp', 'jpe', 'jnp', 'jpo', 'jcxz', 'jecxz', 'jmp']

class Flattener:
	def __init__(self, view, function):
		self._view = view
		self._function = function
		self._name = self._function.symbol.name

		self._arch = self._view.arch
		if self._arch.name not in ['x86', 'x86_64']:
			show_message_box("Djumpo Unchained", "Insupported architecture", OKButtonSet, InformationIcon)
			return

		self._todo = []
		self._visited = []

	def flatten(self, address):
		code = ''
		self._todo.append(address)

		while len(self._todo) > 0:
			address = self._todo.pop()

			if address in self._visited:
				continue

			self._visited.append(address)
			block = self._function.get_basic_block_at(address)
			code += self.process_block(block)

                        # Ensure we follow the immediate branch first
                        for edge in block.outgoing_edges:
                            self._todo.append(edge.target.start)

		return code

	def process_block(self, block):
		code = ''
		asm = block.disassembly_text

		# Add label
		if len(block.incoming_edges) > 0:
			code += "loc_{:x}:\n".format(block.start)

		# Read insts
		for inst in asm:
			code += self.process_inst(inst, block)

		return code

	def process_inst(self, inst, block):
		tokens = inst.tokens
		inst_name = str(tokens[0]).strip()

		if inst_name == 'nop':  # Discard NOPs
			return ''
		elif inst_name == self._name:  # Remove function label
			return ''

		lifted_inst = str(inst)

		# Remove useless {...}
		lifted_inst = re.sub('\{.*\}', '', lifted_inst)

		# Hack aroud stos{b,w,d} insts -- fails to assemble
		lifted_inst = re.sub('(stosb|stosw|stosd).*', '\\1', lifted_inst)

		# Replace tokens with their address
		lifted_inst = re.sub('(sub_|data_)([a-f0-9]+)', '0x\\2', lifted_inst)

		# Handle symbols
		for token in tokens:
			symbol = self._view.get_symbol_by_raw_name(token.text)
			if symbol is not None:
				lifted_inst = lifted_inst.replace(token.text, hex(symbol.address)[:-1])

		edges = block.outgoing_edges
		if edges and inst_name in JUMPS:
                        nb_edges = len(edges)
			if nb_edges == 2 or (nb_edges == 1 and len(edges[0].target.incoming_edges) != 1):
				# Due to instruction removal, original instruction offsets are shifted.
				# In order to preserve CFG structure, branch target addresses are substituted with labels
				lifted_inst = "{} loc_{:x}".format(inst_name, edges[0].target.start)
			# Skip useless JUMPs
			else:
				return ''

		return lifted_inst + '\n'

	def assemble(self, code):
		return self._arch.assemble(code, self._function.start)

def main(view, function):
	flattener = Flattener(view, function)
	code = flattener.flatten(function.start)
	raw, err = flattener.assemble(code)
	if not err:
		view.write(function.start, raw)
	else:
		log.log_warn('failed to de-obfuscate current function')

PluginCommand.register_for_function("Unchain jumps", "De-obfuscate jump chains", main)
