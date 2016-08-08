<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use GMP;
use Mdanter\Ecc\Crypto\Signature\Signature;
use Mdanter\Ecc\Crypto\Signature\SignatureInterface;
use Mdanter\Ecc\Math\GmpMathInterface;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class SignatureSerializer
{
    const LENGTH = [
        'sha256' => 64,
        'sha384' => 96,
        'sha512' => 132,
    ];

    /**
     * @var GmpMathInterface
     */
    private $mathInterface;

    public function __construct(GmpMathInterface $mathInterface)
    {
        $this->mathInterface = $mathInterface;
    }

    public function serialize(SignatureInterface $signature, string $algorithm): string
    {
        return pack(
            'H*',
            sprintf(
                '%s%s',
                $this->addPadding($signature->getR(), self::LENGTH[$algorithm]),
                $this->addPadding($signature->getS(), self::LENGTH[$algorithm])
            )
        );
    }

    private function addPadding(GMP $point, int $length): string
    {
        return str_pad(
            $this->mathInterface->decHex((string) $point),
            $length,
            '0',
            STR_PAD_LEFT
        );
    }

    public function parse(string $expected, string $algorithm): SignatureInterface
    {
        $value = unpack('H*', $expected)[1];

        return new Signature(
            gmp_init($this->mathInterface->hexDec(substr($value, 0, self::LENGTH[$algorithm])), 10),
            gmp_init($this->mathInterface->hexDec(substr($value, self::LENGTH[$algorithm])), 10)
        );
    }
}
