using System;
using System.Data.Entity;
using System.Threading.Tasks;
using System.Net;
using System.Web.Mvc;
using System.Linq;
using cs_aspnet_mvc_crud.Models;
using cs_aspnet_mvc_crud.Middleware.Auth;
using PagedList;
using System.Text.RegularExpressions;
using System.Web.Helpers;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace cs_aspnet_mvc_crud.Controllers
{
    public class UserController : BaseController
    {
        // GET: User
        [UserAuthorization(userActionId: 26)]
        public ActionResult Index(string sortOrder, string currentFilter, string searchString, int? page)
        {
            ViewBag.isAdmin = isAdmin;

            ViewBag.CurrentSort = sortOrder;
            ViewBag.IdSortParm = String.IsNullOrEmpty(sortOrder) ? "id_desc" : "";
            ViewBag.UsernameSortParm = String.IsNullOrEmpty(sortOrder) ? "username_desc" : "";
            ViewBag.EmailSortParm = String.IsNullOrEmpty(sortOrder) ? "email_desc" : "";
            ViewBag.UserPositionNameSortParm = String.IsNullOrEmpty(sortOrder) ? "user_position_name_desc" : "";

            if (searchString != null)
            {
                page = 1;
            }
            else
            {
                searchString = currentFilter;
            }

            ViewBag.CurrentFilter = searchString;

            var users = from o in entityModel.user select o;

            if (!String.IsNullOrEmpty(searchString))
            {
                users = users.Where(o =>
                    o.username.Contains(searchString)
                    || o.email.Contains(searchString)
                    || o.user_position.name.Contains(searchString)
                );
            }

            switch (sortOrder)
            {
                case "id_desc":
                    users = users.OrderByDescending(o => o.id);
                    break;
                case "username_desc":
                    users = users.OrderByDescending(o => o.username);
                    break;
                case "email_desc":
                    users = users.OrderByDescending(o => o.email);
                    break;
                case "created_at_desc":
                    users = users.OrderByDescending(o => o.registration_date);
                    break;
                case "user_position_name_desc":
                    users = users.OrderByDescending(o => o.user_position.name);
                    break;
                default:
                    users = users.OrderBy(o => o.id);
                    break;
            }
            int pageNumber = (page ?? 1);

            return View(users.ToPagedList(pageNumber, this.pageSize));
        }

        // GET: User
        [UserAuthorization(userActionId: 26)]
        public async Task<ActionResult> GetAll()
        {
            var user = entityModel.user.Include(u => u.user_position);
            return View(await user.ToListAsync());
        }

        // GET: User/Details/5
        [UserAuthorization(userActionId: 27)]
        public async Task<ActionResult> Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            user user = await entityModel.user.FindAsync(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }

        // GET: User/Create
        [UserAuthorization(userActionId: 28)]
        public ActionResult Create()
        {
            ViewBag.user_position_id = new SelectList(entityModel.UserPosition, "id", "name");
            return View();
        }

        // POST: User/Create
        // Para protegerse de ataques de publicación excesiva, habilite las propiedades específicas a las que quiere enlazarse. Para obtener 
        // más detalles, vea https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [UserAuthorization(userActionId: 28)]
        public async Task<ActionResult> Create([Bind(Include = "id,username,email,email_confirmed,password_hash,security_stamp,two_factor_enabled,lockout_end_date_utc,lockout_enabled,access_failed,registration_date,user_position_id,active")] user user)
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
                user.active = true;

                bool bandera = false;
                bool banderaCorreo = false;
                bool banderaPass = false;
                var duplicidad = entityModel.user.Where(x => x.email == user.email).FirstOrDefault();

                // Validaciones username
                if (user.username != null)
                {
                    bool isletter = user.username.All(c => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
                    if (isletter == false)
                    {
                        ViewBag.NoLetter = true;
                        bandera = true;
                    }
                }
                else
                {
                    ViewBag.UsernameVacio = true;
                    bandera = true;
                }

                // Validaciones email
                if (user.email == null)
                {
                    ViewBag.EmailVacio = true;
                    banderaCorreo = true;
                }
                else 
                {
                    // Debe contener formato de correo
                    bool formatoEmail = validarEmail(user.email);
                    if (formatoEmail)
                    {
                        banderaCorreo = false;
                    }
                    else
                    {
                        ViewBag.EmailFormato = true;
                        banderaCorreo = true;
                    }
                }

                if (duplicidad != null)
                {
                    ViewBag.Duplicidad = true;
                    banderaCorreo = true;
                }

                // Validaciones Password
                if (user.password_hash == null)
                {
                    ViewBag.PasswordVacio = true;
                    banderaPass = true;
                }
                else
                {
                    // No caracteres especiales
                    bool iscorrect = user.password_hash.All(Char.IsLetterOrDigit);
                    if (iscorrect == false)
                    {
                        ViewBag.NoCorrect = true;
                        banderaPass = true;
                    }
                    else
                    {
                        // Debe contener por lo menos un numero y una letra
                        string caracteres = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                        string palabra = user.password_hash;
                        bool hayCoincidencias = (caracteres.Intersect(palabra).Count() > 0);
                        string numeros = "1234567890";
                        string numero = user.password_hash;
                        bool hayCoincidenciasNum = (numeros.Intersect(numero).Count() > 0);
                        if (hayCoincidencias == true && hayCoincidenciasNum == true)
                        {
                            banderaPass = false;
                        }
                        else
                        {
                            ViewBag.NumberLetterPass = true;
                            banderaPass = true;
                        }
                    }
                }

                if (bandera || banderaCorreo || banderaPass)
                {
                    ViewBag.user_position_id = new SelectList(entityModel.UserPosition, "id", "name", user.user_position_id);
                    return View(user);
                }
                else
                {
                    user.password_hash = ComputeSHA256(user.password_hash);
                    await entityModel.SaveChangesAsync();
                    return RedirectToAction("Index");
                }

            }

            ViewBag.user_position_id = new SelectList(entityModel.UserPosition, "id", "name", user.user_position_id);
            return View(user);
        }

        public static bool validarEmail(string email)
        {
            // Compara con la expresion regular de correo
            return Regex.IsMatch(email, @"^(?("")("".+?""@)|(([0-9a-zA-Z]((\.(?!\.))|[-!#\$%&'\*\+/=\?\^`\{\}\|~\w])*)(?<=[0-9a-zA-Z])@))" + @"(?(\[)(\[(\d{1,3}\.){3}\d{1,3}\])|(([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,6}))$");
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


        public string descifrarTextoAES(string textoCifrado, string palabraPaso,
            string valorRGBSalt, string algoritmoEncriptacionHASH,
            int iteraciones, string vectorInicial, int tamanoClave)
        {
            try
            {
                byte[] InitialVectorBytes = Encoding.ASCII.GetBytes(vectorInicial);
                byte[] saltValueBytes = Encoding.ASCII.GetBytes(valorRGBSalt);

                byte[] cipherTextBytes = Convert.FromBase64String(textoCifrado);

                PasswordDeriveBytes password =
                    new PasswordDeriveBytes(palabraPaso, saltValueBytes,
                        algoritmoEncriptacionHASH, iteraciones);

                byte[] keyBytes = password.GetBytes(tamanoClave / 8);

                RijndaelManaged symmetricKey = new RijndaelManaged();

                symmetricKey.Mode = CipherMode.CBC;

                ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, InitialVectorBytes);

                MemoryStream memoryStream = new MemoryStream(cipherTextBytes);

                CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);

                byte[] plainTextBytes = new byte[cipherTextBytes.Length];

                int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);

                memoryStream.Close();
                cryptoStream.Close();

                string textoDescifradoFinal = Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);

                return textoDescifradoFinal;
            }
            catch
            {
                return null;
            }
        }

        // GET: User/Edit/5
        [UserAuthorization(userActionId: 29)]
        public async Task<ActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            user user = await entityModel.user.FindAsync(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            ViewBag.user_position_id = new SelectList(entityModel.UserPosition, "id", "name", user.user_position_id);
            return View(user);
        }

        // POST: User/Edit/5
        // Para protegerse de ataques de publicación excesiva, habilite las propiedades específicas a las que quiere enlazarse. Para obtener 
        // más detalles, vea https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [UserAuthorization(userActionId: 29)]
        public async Task<ActionResult> Edit([Bind(Include = "id,username,email,email_confirmed,password_hash,security_stamp,two_factor_enabled,lockout_end_date_utc,lockout_enabled,access_failed,registration_date,user_position_id,active")] user user)
        {
            if (ModelState.IsValid)
            {
                bool bandera = false;
                bool banderaCorreo = false;
                bool banderaPass = false;
                var duplicidad = entityModel.user.Where(x => x.email == user.email && x.id != user.id).FirstOrDefault();

                // Validaciones username
                if (user.username != null)
                {
                    bool isletter = user.username.All(c => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
                    if (isletter == false)
                    {
                        ViewBag.NoLetter = true;
                        bandera = true;
                    }
                }
                else
                {
                    ViewBag.UsernameVacio = true;
                    bandera = true;
                }

                // Validaciones email
                if (user.email == null)
                {
                    ViewBag.EmailVacio = true;
                    banderaCorreo = true;
                }
                else
                {
                    // Debe contener formato de correo
                    bool formatoEmail = validarEmail(user.email);
                    if (formatoEmail)
                    {
                        banderaCorreo = false;
                    }
                    else
                    {
                        ViewBag.EmailFormato = true;
                        banderaCorreo = true;
                    }
                }

                if (duplicidad != null)
                {
                    ViewBag.Duplicidad = true;
                    banderaCorreo = true;
                }

                // Validaciones Password
                if (user.password_hash == null)
                {
                    ViewBag.PasswordVacio = true;
                    banderaPass = true;
                }
                else
                {
                    // No caracteres especiales
                    bool iscorrect = user.password_hash.All(Char.IsLetterOrDigit);
                    if (iscorrect == false)
                    {
                        ViewBag.NoCorrect = true;
                        banderaPass = true;
                    }
                    else
                    {
                        // Debe contener por lo menos un numero y una letra
                        string caracteres = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                        string palabra = user.password_hash;
                        bool hayCoincidencias = (caracteres.Intersect(palabra).Count() > 0);
                        string numeros = "1234567890";
                        string numero = user.password_hash;
                        bool hayCoincidenciasNum = (numeros.Intersect(numero).Count() > 0);
                        if (hayCoincidencias == true && hayCoincidenciasNum == true)
                        {
                            banderaPass = false;
                        }
                        else
                        {
                            ViewBag.NumberLetterPass = true;
                            banderaPass = true;
                        }
                    }
                }

                if (bandera || banderaCorreo || banderaPass)
                {
                    ViewBag.user_position_id = new SelectList(entityModel.UserPosition, "id", "name", user.user_position_id);
                    return View(user);
                }
                else
                {
                    user.password_hash = ComputeSHA256(user.password_hash);
                    entityModel.Entry(user).State = EntityState.Modified;
                    await entityModel.SaveChangesAsync();

                    return RedirectToAction("Index");
                }

                //entityModel.Entry(user).State = EntityState.Modified;
                //await entityModel.SaveChangesAsync();

                //return RedirectToAction("Index");
            }
            ViewBag.user_position_id = new SelectList(entityModel.UserPosition, "id", "name", user.user_position_id);
            return View(user);
        }

        // GET: User/Delete/5
        [UserAuthorization(userActionId: 30)]
        public async Task<ActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            user user = await entityModel.user.FindAsync(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }

        // POST: User/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        [UserAuthorization(userActionId: 30)]
        public async Task<ActionResult> DeleteConfirmed(int id)
        {
            user user = await entityModel.user.FindAsync(id);
            entityModel.user.Remove(user);
            await entityModel.SaveChangesAsync();
            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                entityModel.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
