<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use GMP;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Mdanter\Ecc\Random\RandomNumberGeneratorInterface;

/**
 * PHPECC adapter in order to simplify ECDSA base signer
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
class EccAdapter
{
    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var GeneratorPoint
     */
    private $generatorPoint;

    /**
     * @var SignatureSerializer
     */
    private $serializer;

    /**
     * @var RandomNumberGeneratorInterface
     */
    private $numberGenerator;

    public function __construct(
        GmpMathInterface $mathInterface,
        Signer $signer = null,
        GeneratorPoint $generatorPoint = null,
        SignatureSerializer $serializer = null,
        RandomNumberGeneratorInterface $numberGenerator = null
    ) {
        $this->signer = $signer ?: EccFactory::getSigner($mathInterface);
        $this->generatorPoint = $generatorPoint ?: EccFactory::getNistCurves($mathInterface)->generator521();
        $this->serializer = $serializer ?: new SignatureSerializer($mathInterface);
        $this->numberGenerator = $numberGenerator ?: RandomGeneratorFactory::getRandomGenerator();
    }

    public function createHash(
        PrivateKeyInterface $key,
        GMP $signingHash,
        string $algorithm
    ): string {
        return $this->serializer->serialize(
            $this->signer->sign(
                $key,
                $signingHash,
                $this->numberGenerator->generate($key->getPoint()->getOrder())
            ),
            $algorithm
        );
    }

    public function verifyHash(
        string $expected,
        PublicKeyInterface $key,
        GMP $signingHash,
        string $algorithm
    ): bool {
        return $this->signer->verify(
            $key,
            $this->serializer->parse($expected, $algorithm),
            $signingHash
        );
    }

    public function createSigningHash(
        string $payload,
        string $algorithm
    ): GMP {
        return $this->signer->hashData(
            $this->generatorPoint,
            $algorithm,
            $payload
        );
    }
}
