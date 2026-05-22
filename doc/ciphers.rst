.. _ciphers:

Cipher functions
================

.. module:: nettle.ciphers

Example
-------
.. doctest::

   >>> import nettle
   >>> encryptor = nettle.AES128(encrypt_key=b'\x00\x01\x02\x03\x05\x06\x07\x08\n\x0b\x0c\r\x0f\x10\x11\x12')
   >>> decryptor = nettle.AES128(decrypt_key=b'\x00\x01\x02\x03\x05\x06\x07\x08\n\x0b\x0c\r\x0f\x10\x11\x12')
   >>> ciphertext = encryptor.encrypt(b'Secret Message!\0')
   >>> ciphertext
   b'\x1a\xcb8,}!\x0f\xa7\x80\xbb\xd8e\x98.\x93\x04'
   >>> decryptor.decrypt(ciphertext)
   b'Secret Message!\x00'


Recommended ciphers
-------------------
   
AES
^^^

.. autoclass:: AES128
   :members: set_encrypt_key, set_decrypt_key, invert_key, encrypt, decrypt

.. autoclass:: AES192
   :members: set_encrypt_key, set_decrypt_key, invert_key, encrypt, decrypt


	  
Module contents
---------------

.. automodule:: nettle.ciphers
   :members:
   :show-inheritance:
   :no-index:
