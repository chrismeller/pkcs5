<?php

	namespace PKCS5;

	class PKCS5 {
		
		public static function pbkdf2 ( $password, $salt ) {
			
			return new PBKDF2( $password, $salt );
			
		}
		
		public static function pbes2 ( $password, $salt ) {
			
			return new PBES2( $password, $salt );
			
		}
		
	}

?>