<?php

	abstract class PKCS5_Pad {
		
		abstract function pad ( $data, $block_size );
		abstract function unpad ( $data, $block_size );
		
	}

?>