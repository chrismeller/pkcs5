<?php

	class PBES2 {
		
		public $iterations = 1000;
		public $length = 32;
		public $algorithm = 'sha256';
		public $cipher = 'aes256';
		public $pad = 'RFC1423';
		public $mode = 'CBC';
		public $iv = null;
		
		private $password;
		private $salt;
		private $data;
		
		public function __construct ( $password, $salt ) {
			
			$this->password = $password;
			$this->salt = $salt;
			
			$pad_class = 'PKCS5_Pad_' . $this->pad;
			
			$this->pad = new $pad_class();
			
		}
		
		public static function factory ( $password, $salt ) {
			
			return new PBES2( $password, $salt );
			
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
		 * Convenience method for chaining with the factory.
		 * @param string $cipher
		 */
		public function cipher ( $cipher ) {
			
			$this->cipher = $cipher;
			
			return $this;
			
		}
		
		/**
		 * Convenience method for chaining with the factory.
		 * @param string $pad
		 */
		public function pad ( $pad ) {
			
			$this->pad = $pad;
			
			return $this;
			
		}
		
		/**
		 * Convenience method for chaining with the factory.
		 * @param string $iv
		 */
		public function iv ( $iv ) {
			
			$this->iv = $iv;
			
			return $this;
			
		}
		
		/**
		 * Convenience method for chaining with the factory.
		 * @param string $mode
		 */
		public function mode ( $mode ) {
			
			$this->mode = $mode;
			
			return $this;
			
		}
		
		public function encrypt ( $data, $as_hex = true ) {
			
			$module = $this->module_setup();
			
			$encrypted = mcrypt_generic( $module, $data );
			
			// pad the encrypted value to the right block size
			if ( $this->pad !== null ) {
				$encrypted = $this->pad->pad( $encrypted, mcrypt_enc_get_block_size( $module ) );
			}
			
			$this->module_teardown( $module );
			
			if ( $as_hex ) {
				return bin2hex( $encrypted );
			}
			else {
				return $encrypted;
			}
			
		}
		
		private function module_setup ( ) {
			
			// create the hash object and get the derived key
			$hash = PBKDF2::factory( $this->password, $this->salt )
				->length( $this->length )
				->iterations( $this->iterations )
				->algorithm( $this->algorithm )
				->hash();
			
			// figure out the actual cipher constant if it's one of our custom strings
			// note that the RIJNDAEL ciphers were the ones selected in the AES standardization process, so they're synonyms
			switch ( $this->cipher ) {
				case 'aes':
				case 'aes128':
				case 'aes_128':
					$cipher = MCRYPT_RIJNDAEL_128;
					break;
				
				case 'aes192':	
				case 'aes_192':
					$cipher = MCRYPT_RIJNDAEL_192;
					break;
				
				case 'aes256':	
				case 'aes_256':
					$cipher = MCRYPT_RIJNDAEL_256;
					break;
					
				case '3des':
					$cipher = MCRYPT_3DES;
					break;
					
				default:
					// by default assume it's an MCRYPT_* constant
					$cipher = $this->cipher;
					break;
			}
			
			// figure out the proper MCRYPT_MODE_* constant for our mode
			switch ( $this->mode ) {
				case 'CBC':
					// note that CBC mode can optionally have an IV
					$mode = MCRYPT_MODE_CBC;
					break;
					
				case 'OFB':
					// note that OFB mode requires an IV
					$mode = MCRYPT_MODE_OFB;
					break;
					
				case 'CFB':
					// note that CFB mode requires an IV
					$mode = MCRYPT_MODE_CFB;
					break;
					
				case 'ECB':
					$mode = MCRYPT_MODE_ECB;
					break;
					
				default:
					// by default assume it's an MCRYPT_MODE_* constant
					$mode = $this->mode;
					break;
			}
			
			// open the proper mcrypt module
			$module = mcrypt_module_open( $cipher, '', $mode, '' );
			
			// now get all the sizes we need to remember
			$key_size = mcrypt_enc_get_key_size( $module );
			$iv_size = mcrypt_enc_get_iv_size( $module );
			$block_size = mcrypt_enc_get_block_size( $module );
			
			// the IV has to be the same on encryption and decryption. if one wasn't specified, use a string of 0's
			if ( $this->iv === null ) {
				$iv = str_repeat( '0', $iv_size );
			}
			else {
				
				$iv = $this->iv;
				
				// an IV was supplied. if it's not long enough, pad it with 0's
				if ( strlen( $iv ) < $iv_size ) {
					$iv = str_pad( $iv, $iv_size, '0' );
				}
				
			}
			
			// make sure the hash we generated isn't longer than the key can be for this crypt module
			$key = substr( $hash, 0, $key_size );
			
			// initialize the encryption handler with our hash and IV
			mcrypt_generic_init( $module, $key, $iv );
			
			return $module;
			
		}
		
		private function module_teardown ( $module ) {
			
			// terminate the encryption handler
			mcrypt_generic_deinit( $module );
			
			// close the mcrypt module
			mcrypt_module_close( $module );
			
		}
		
		public function decrypt ( $data ) {
			
			$module = $this->module_setup();
			
			// unpad the data before we try to decrypt it
			if ( $this->pad !== null ) {
				$data = $this->pad->unpad( $data, mcrypt_enc_get_block_size( $module ) );
			}
			
			$decrypted = mdecrypt_generic( $module, $data );
			
			$this->module_teardown( $module );
			
			return $decrypted;
			
		}
		
	}

?>