<?php

	class PKCS5_Pad_RFC1423 extends PKCS5_Pad {
		
		public function pad ( $data, $block_size ) {
			
			$pad = $block_size - ( strlen( $data ) % $block_size );
			
			return $data . str_repeat( chr( $pad ), $pad );
			
		}
		
		public function unpad ( $data, $block_size ) {
			
			$pad = ord( substr( $data, -1 ) );
			
			if ( $pad > $block_size ) {
				return false;
			}
			
			if ( $pad === strspn( $data, chr( $pad ), -$pad ) ) {
				return substr( $data, 0, -1 * $pad );
			}
			else {
				return false;
			}
			
		}
		
	}

?>