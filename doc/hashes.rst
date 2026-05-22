.. _hashes:

Hash functions
==============

.. module:: nettle.hashes


Example
-------
.. doctest::


   >>> import nettle
   >>> sha = nettle.SHA256()
   >>> sha.update(b'abc')
   >>> sha.hexdigest()
   'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

   >>> nettle.SHA256(b'abc').digest()
   b'\xbax\x16\xbf\x8f\x01\xcf\xeaAA@\xde]\xae"#\xb0\x03a\xa3\x96\x17z\x9c\xb4\x10\xffa\xf2\x00\x15\xad'

Recommended hashes
------------------ 
   
SHA2
^^^^

.. autoclass:: SHA256
   :members: update, digest, hexdigest

.. autoclass:: SHA512
   :members: update, digest, hexdigest


SHA3
^^^^

.. autoclass:: SHA3_128
   :members: update, shake, shake_output


.. autoclass:: SHA3_224
   :members: update, digest, hexdigest

.. autoclass:: SHA3_256
   :members: update, digest, hexdigest, shake, shake_output
	  
Module contents
---------------

.. automodule:: nettle.hashes
   :members:
   :show-inheritance:
   :no-index:
