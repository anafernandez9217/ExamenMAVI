
//------------------------------------------------------------------------------
// <auto-generated>
//     Este código se generó a partir de una plantilla.
//
//     Los cambios manuales en este archivo pueden causar un comportamiento inesperado de la aplicación.
//     Los cambios manuales en este archivo se sobrescribirán si se regenera el código.
// </auto-generated>
//------------------------------------------------------------------------------


namespace cs_aspnet_mvc_crud.Models
{

using System;
    using System.Collections.Generic;
    
public partial class module
{

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
    public module()
    {

        this.user_action = new HashSet<user_action>();

    }


    public int id { get; set; }

    public string name { get; set; }

    public string description { get; set; }

    public int module_category_id { get; set; }



    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]

    public virtual ICollection<user_action> user_action { get; set; }

}

}
