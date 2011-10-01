<?php

	class PBKDF2 {
		
		public $iterations = 1000;
		public $length = 32;
		public $algorithm = 'sha1';
		
		private $password;
		private $salt;
		
		public function __construct ( $password, $salt ) {
			
			$this->password = $password;
			$this->salt = $salt;
			
		}
		
		public static function factory ( $password, $salt ) {
			
			return new PBKDF2( $password, $salt );
			
		}
		
		/**
		 * Convenience method for chaining with the factory.
		 * @param string $password
		 */
		public function password ( $password ) {
			
			$this->password = $password;
			
			return $this;
			
		}
		
		/**
		 * Convenience method for chaining with the factory.
		 * @param string $salt
		 */
		public function salt ( $salt ) {
			
			$this->salt = $salt;
			
			return $this;
			
		}
		
		/**
		 * Convenience method for chaining with the factory.
		 * @param int $iterations
		 */
		public function iterations ( $iterations ) {
			
			$this->iterations = $iterations;
			
			return $this;
			
		}
		
		/**
		 * Convenience method for chaining with the factory.
		 * @param int $length
		 */
		public function length ( $length ) {
			
			$this->length = $length;
			
			return $this;
			
		}
		
		/**
		 * Convenience method for chaining with the factory.
		 * @param string $algorithm
		 */
		public function algorithm ( $algorithm ) {
			
			$this->algorithm = $algorithm;
			
			return $this;
			
		}
		
		/**
		 * This is an implementation of PBKDF2 adapted from the one by Andrew Johnson at 
		 * 		http://www.itnewb.com/v/Encrypting-Passwords-with-PHP-for-Storage-Using-the-RSA-PBKDF2-Standard
		 * 
		 * It should conform to the process in the PKCS #5: Password-Based Cryptography Standard, version 2.0 (March 25, 1999) specification 
		 * 		http://www.rsa.com/rsalabs/node.asp?id=2127
		 * The steps indicated are those specified in the spec, section 5.2: PBKDF2 
		 * 
		 * @param boolean $as_hex Return the hex-encoded string representation instead of binary data. Good for storing in a database as varchar instead of blob.
		 */
		public function hash ( $as_hex = true ) {
			
			// first, see how long the hash will be for the selected algorithm
			$hash_length = strlen( hash( $this->algorithm, null, true ) );
			
			// what is the largest key we could generate with this algorithm?
			$max_length = ( pow(2, 23) - 1 ) * $hash_length;
			
			// step 1: if the requested length is longer than the length of the key we can generate with this algorithm, throw an error
			if ( $this->length > $max_length ) {
				throw new LengthException('derived key too long');
			}
			
			// step 2: figure out how many blocks of hash length will be in the derived key, rounding up
			$key_blocks = ceil( $this->length / $hash_length );
			
			// initialize the final key
			$derived_key = '';
			
			// step 3: generate each required block for the key
			for ( $block = 1; $block <= $key_blocks; $block++ ) {
				
				// initial hash for this block - note that password is the key, salt is the text ('data' in php's docs), per Appendix B.1.1
				// 		note that pack('N') means a 32-bit big-endian number (ie: "four-octet encoding... most significant octet first" in the RFC)
				$initial_block = $b = hash_hmac( $this->algorithm, $this->salt . pack('N', $block), $this->password, true );
				
				// perform block iterations
				// 		the < is intentional. it should not be <= for unknown reasons
				for ( $i = 1; $i < $this->iterations; $i++ ) {
					
					// XOR each iterate
					$initial_block ^= ( $b = hash_hmac( $this->algorithm, $b, $this->password, true ) );
					
				}
				
				// step 4: append the iterated block to the final key
				$derived_key .= $initial_block;
				
			}
			
			// step 4: extract the first $length characters of the derived key
			$hash = substr( $derived_key, 0, $this->length );
			
			// step 5: output the derived key
			if ( $as_hex ) {
				return bin2hex($hash);
			}
			else {
				return $hash;
			}
			
		}
		
	}

?>