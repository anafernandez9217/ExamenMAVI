using System;
using System.Data.Entity;
using System.Threading.Tasks;
using System.Net;
using System.Web.Mvc;
using System.Linq;
using cs_aspnet_mvc_crud.Models;
using cs_aspnet_mvc_crud.Middleware.Auth;
using PagedList;

namespace cs_aspnet_mvc_crud.Controllers
{
    public class ContactoController : BaseController
    {
        // GET: Contacto
        [UserAuthorization(userActionId: 21)]
        public ActionResult Index(string sortOrder, string currentFilter, string searchString, int? page)
        {
            ViewBag.isAdmin = isAdmin;

            ViewBag.CurrentSort = sortOrder;
            ViewBag.IdSortParm = String.IsNullOrEmpty(sortOrder) ? "id_desc" : "";
            ViewBag.UserPositionNameSortParm = String.IsNullOrEmpty(sortOrder) ? "user_phone_name_desc" : "";
            ViewBag.UserActionNameSortParm = String.IsNullOrEmpty(sortOrder) ? "user_user_name_desc" : "";

            if (searchString != null)
            {
                page = 1;
            }
            else
            {
                searchString = currentFilter;
            }

            ViewBag.CurrentFilter = searchString;

            var contacto = from o in entityModel.contacto select o;

            if (!String.IsNullOrEmpty(searchString))
            {
                contacto = contacto.Where(o =>
                    o.Phone.Contains(searchString)
                    || o.user.username.Contains(searchString)
                );
            }

            switch (sortOrder)
            {
                case "id_desc":
                    contacto = contacto.OrderByDescending(o => o.id);
                    break;
                case "user_phone_name_desc":
                    contacto = contacto.OrderByDescending(o => o.Phone);
                    break;
                case "created_at_desc":
                    contacto = contacto.OrderByDescending(o => o.registration_date);
                    break;
                case "user_user_name_desc":
                    contacto = contacto.OrderByDescending(o => o.user.username);////
                    break;
                default:
                    contacto = contacto.OrderBy(o => o.id);
                    break;
            }
            int pageNumber = (page ?? 1);

            return View(contacto.ToPagedList(pageNumber, this.pageSize));
            //return View(contacto);
        }

        // GET: Contacto
        [UserAuthorization(userActionId: 21)]
        public async Task<ActionResult> GetAll()
        {
            var user_permission = entityModel.contacto.Include(u => u.user_id);
            return View(await user_permission.ToListAsync());
        }

        // GET: Contacto/Details/5
        [UserAuthorization(userActionId: 22)]
        public async Task<ActionResult> Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            contacto contacto = await entityModel.contacto.FindAsync(id);
            if (contacto == null)
            {
                return HttpNotFound();
            }
            return View(contacto);
        }

        // GET: Contacto/Create
        [UserAuthorization(userActionId: 23)]
        public ActionResult Create()
        {
            ViewBag.user_id = new SelectList(entityModel.user, "id", "username");
            return View();
        }

        // POST: Contacto/Create
        // Para protegerse de ataques de publicación excesiva, habilite las propiedades específicas a las que quiere enlazarse. Para obtener 
        // más detalles, vea https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [UserAuthorization(userActionId: 23)]
        public async Task<ActionResult> Create([Bind(Include = "id,registration_date,Phone,user_id")] contacto contacto)
        {
            if (ModelState.IsValid)
            {
                contacto.registration_date = DateTime.Now.ToUniversalTime();
                bool bandera = false;

                // Validaciones username
                if (contacto.Phone != null)
                {
                    bool isletter = contacto.Phone.All(c => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
                    if (isletter == true)
                    {
                        ViewBag.NoLetter = true;
                        bandera = true;
                    }
                    else
                    {
                        int numCaracteres = 0;
                        for (int i = 0; i < contacto.Phone.Length; i++)
                        {
                            numCaracteres++;
                        }

                        if (numCaracteres != 10)
                        {
                            ViewBag.Cantidad = true;
                            bandera = true;
                        }
                    }
                }
                else
                {
                    ViewBag.PhoneVacio = true;
                    bandera = true;
                }

                if (bandera)
                {
                    ViewBag.user_id = new SelectList(entityModel.user, "id", "username", contacto.user_id);
                    return View(contacto);
                }
                else
                {
                    entityModel.contacto.Add(contacto);
                    await entityModel.SaveChangesAsync();
                    return RedirectToAction("Index");

                }

            }

            ViewBag.user_id = new SelectList(entityModel.user, "id", "username", contacto.user_id);
            return View(contacto);
        }

        // GET: Contacto/Edit/5
        [UserAuthorization(userActionId: 24)]
        public async Task<ActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            contacto contacto = await entityModel.contacto.FindAsync(id);
            if (contacto == null)
            {
                return HttpNotFound();
            }
            ViewBag.user_id = new SelectList(entityModel.user, "id", "username", contacto.user_id);
            return View(contacto);
        }

        // POST: Contacto/Edit/5
        // Para protegerse de ataques de publicación excesiva, habilite las propiedades específicas a las que quiere enlazarse. Para obtener 
        // más detalles, vea https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [UserAuthorization(userActionId: 24)]
        public async Task<ActionResult> Edit([Bind(Include = "id,registration_date,Phone,user_id")] contacto contacto)
        {
            if (ModelState.IsValid)
            {
                bool bandera = false;

                // Validaciones username
                if (contacto.Phone != null)
                {
                    bool isletter = contacto.Phone.All(c => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
                    if (isletter == true)
                    {
                        ViewBag.NoLetter = true;
                        bandera = true;
                    }
                    else
                    {
                        int numCaracteres = 0;
                        for (int i = 0; i < contacto.Phone.Length; i++)
                        {
                            numCaracteres++;
                        }

                        if (numCaracteres != 10)
                        {
                            ViewBag.Cantidad = true;
                            bandera = true;
                        }
                    }
                }
                else
                {
                    ViewBag.PhoneVacio = true;
                    bandera = true;
                }

                if (bandera)
                {
                    ViewBag.user_id = new SelectList(entityModel.user, "id", "username", contacto.user_id);
                    return View(contacto);
                }
                else
                {
                    entityModel.Entry(contacto).State = EntityState.Modified;
                    await entityModel.SaveChangesAsync();
                    return RedirectToAction("Index");

                }

                //entityModel.Entry(contacto).State = EntityState.Modified;
                //await entityModel.SaveChangesAsync();
                //return RedirectToAction("Index");
            }
            ViewBag.user_id = new SelectList(entityModel.user, "id", "username", contacto.user_id);
            return View(contacto);
        }

        // GET: Contacto/Delete/5
        [UserAuthorization(userActionId: 25)]
        public async Task<ActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            contacto contacto = await entityModel.contacto.FindAsync(id);
            if (contacto == null)
            {
                return HttpNotFound();
            }
            return View(contacto);
        }

        // POST: Contacto/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        [UserAuthorization(userActionId: 25)]
        public async Task<ActionResult> DeleteConfirmed(int id)
        {
            contacto contacto = await entityModel.contacto.FindAsync(id);
            entityModel.contacto.Remove(contacto);
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
