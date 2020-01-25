"""
Protocol-related functions go here
"""


def generate_post_material(
        openbp_version,
        post_key,
        hyperlinks,
        hyperlinks_content_size,
        hyperlinks_content_type,
        hyperlink_content_checksum,
        other_post_key,
        other_checksum,
        **kwargs):

    # There are two optional fields, rel and other

    post_material = {
            'openbp': openbp_version,
            'pk': post_key,
            'docs': hyperlinks,
            'size': hyperlinks_content_size,
            'type': hyperlinks_content_type,
            'chk': hyperlink_content_checksum,
            'other.pk': other_post_key,
            'other.chk': other_checksum
            }

    post_material.update(kwargs)

    return post_material
