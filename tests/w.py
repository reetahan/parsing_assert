import numpy as np
import unittest
import pytest


def sixty_functor(potato):
	return 9+10

def elephant_fairy(nice, num):
	assert 5 == 5
	assert 10 - 6 == 4
	return True

def chlorine(num, strt):
	assert 'a' == 'a'
	elephant_fairy('test',7)
	np.sum([3,4,5])
	return True

def xy():
	return 9-5

class Temp_Test(unittest.TestCase):

	def test_eq(self):
		self.assertEqual(5,5)
		assert 21 - 10 == 11
		self.assertEqual(5,6)


if __name__ == '__main__':
    unittest.main()
    