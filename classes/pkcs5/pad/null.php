<?php

	class PKCS5_Pad_Null extends PKCS5_Pad {
		
		public function pad ( $data, $block_size ) {
			
			$blocks = ceil( strlen( $data ) / $block_size );
			
			return str_pad( $data, $blocks * $block_size, "\0", STR_PAD_RIGHT );
			
		}
		
		public function unpad ( $data, $block_size ) {
			
			return rtrim( $data, "\0" );
			
		}
		
	}

?>