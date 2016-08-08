<?php
namespace Lcobucci\JWT\Signer\Ecdsa;

use Mdanter\Ecc\Math\GmpMathInterface;

abstract class BaseTestCase extends \PHPUnit_Framework_TestCase
{
    /**
     * @var GmpMathInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $mathInterface;

    /**
     * @var EccAdapter|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $adapter;

    /**
     * @var KeyParser|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $keyParser;

    /**
     * @before
     */
    public function createDependencies()
    {
        $this->mathInterface = $this->createMock(GmpMathInterface::class);
        $this->adapter = $this->createMock(EccAdapter::class);
        $this->keyParser = $this->createMock(KeyParser::class);
    }


}
