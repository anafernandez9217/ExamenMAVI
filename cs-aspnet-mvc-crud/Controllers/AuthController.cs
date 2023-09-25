using cs_aspnet_mvc_crud.Models;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace cs_aspnet_mvc_crud.Controllers
{
    public class AuthController : BaseController
    {
        //GET: Auth
        public ActionResult Index()
        {
            if (Session["field_user"] != null)
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        // GET: Login
        public ActionResult Login()
        {
            if (Session["field_user"] != null)
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        // POST: Login
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(string field_user, string field_pass)
        {
            try
            {
                using (Models.DBEntities entityModel = new Models.DBEntities())
                {
                    string hash = ComputeSHA256(field_pass);
                    var userModel = (
                        from u in entityModel.user
                        where u.email == field_user.Trim() || u.username == field_user.Trim() && u.password_hash == hash.Trim()
                        select u).FirstOrDefault();

                    if (userModel == null)
                    {
                        ViewBag.Error = "El usuario o la constraseña no son validos.";
                        return View();
                    }

                    var userName = entityModel.user.Where(x => x.email == field_user).FirstOrDefault();

                    if (userName == null)
                    {
                        ViewBag.Error = "El usuario es incorrecto.";
                        return View();
                    }

                    var userPass = entityModel.user.Where(x => x.password_hash == hash).FirstOrDefault();

                    if (userPass == null)
                    {
                        ViewBag.Error = "La contraseña es incorrecta.";
                        return View();
                    }


                    Session["field_user"] = userModel;   
                    
                    if(userModel.user_position_id == 1)
                    {
                        isAdmin = true;
                    }
                    else
                    {
                        isAdmin = false;
                    }
                }

                return RedirectToAction("Index", "Home");
            }
            catch (Exception ex)
            {
                ViewBag.Error = ex.Message;
                return View();
            }
        }

        // Cifrado Hash 
        static string ComputeSHA256(string password)
        {
            string hash = String.Empty;

            // Inicializar un objeto hash SHA256
            using (SHA256 sha256 = SHA256.Create())
            {
                // Calcular el hash de la cadena dada
                byte[] hashValue = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));

                // Convierte la matriz de bytes a formato de cadena
                foreach (byte b in hashValue)
                {
                    hash += $"{b:X2}";
                }
            }

            return hash;
        }

        // GET: Logout
        public ActionResult Logout()
        {
            HttpCookie cookie = new HttpCookie("Cookie1", "");
            cookie.Expires = DateTime.Now.AddYears(-1);
            Response.Cookies.Add(cookie);

            FormsAuthentication.SignOut();

            Session["field_user"] = null;
            return RedirectToAction("Index", "Home");
        }

        // POST: SignUp
        public ActionResult SignUp()
        {
            if (Session["field_user"] != null)
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        // POST: SignUp
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SignUp([Bind(Include = "id,username,email,email_confirmed,password_hash,security_stamp,two_factor_enabled,lockout_end_date_utc,lockout_enabled,access_failed,first_name,last_name,picture,created_at,user_position_id,registration_date")] user user)
        {
            try
            {
                using (DBEntities entityModel = new DBEntities())
                {
                    if (ModelState.IsValid)
                    {
                        entityModel.user.Add(user);
                        user.email_confirmed = false;
                        user.security_stamp = null;
                        user.two_factor_enabled = false;
                        user.lockout_end_date_utc = null;
                        user.lockout_enabled = false;
                        user.access_failed_count = 0;
                        user.registration_date = DateTime.Now.ToUniversalTime();
                        user.user_position_id = 2;
                        await entityModel.SaveChangesAsync();
                    }

                    if (entityModel == null)
                    {
                        ViewBag.Error = "The user is not valid.";
                        return View();
                    }
                }
                ViewBag.Message = "Submit successfully.";
                return View();
            }
            catch (Exception ex)
            {
                ViewBag.Error = ex.Message;
                return View();
            }
        }
    }
}