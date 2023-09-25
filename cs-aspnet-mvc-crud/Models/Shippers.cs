using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

// Validaciones con
using System.ComponentModel.DataAnnotations;

namespace Crud_Dos.Models
{
    public class Shippers
    {
        [Required]
        public int ShipperId { get; set; }
        [Required]
        public string CompanyName { get; set; }
        [Required]
        public string Phone { get; set; }

        // Constructor
        public Shippers()
        {
            
        }

        // Constructor Sobrecarga
        public Shippers(int id, string nombre, string tel)
        {
            this.ShipperId = id;
            this.CompanyName = nombre;
            this.Phone = tel;
        }
    }
}