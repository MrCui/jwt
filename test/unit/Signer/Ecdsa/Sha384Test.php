<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class Sha384Test extends BaseTestCase
{
    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Ecdsa
     *
     * @covers Lcobucci\JWT\Signer\Ecdsa\Sha384::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect()
    {
        $this->assertEquals('ES384', $this->getSigner()->getAlgorithmId());
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Ecdsa
     *
     * @covers Lcobucci\JWT\Signer\Ecdsa\Sha384::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect()
    {
        $this->assertEquals('sha384', $this->getSigner()->getAlgorithm());
    }

    private function getSigner(): Sha384
    {
        return new Sha384(
            $this->mathInterface,
            $this->adapter,
            $this->keyParser
        );
    }
}
