using Microsoft.IdentityModel.JsonWebTokens;
using Project2.Controllers;

namespace TestProject2
{
    public class UnitTest1
    {
        [Fact]
        public void AuthReturnsValidJWT()
        {
            //Arrange
            var controller = new ValuesController();

            //Act
            var actionResult = controller.Auth("false");
            JsonWebToken jwt = new JsonWebToken(actionResult);

            //Assert
            Assert.True(jwt.ValidTo > DateTime.Now);
        }

        [Fact]
        public void AuthReturnsInvalidJWT()
        {
            //Arrange
            var controller = new ValuesController();

            //Act
            var actionResult = controller.Auth("true");
            JsonWebToken jwt = new JsonWebToken(actionResult);

            //Assert
            Assert.True(jwt.ValidTo < DateTime.Now);
        }
    }
}